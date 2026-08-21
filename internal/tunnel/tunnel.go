// Package tunnel wires the FlexBraid pipeline together. It implements the
// client and server roles that pass inner WireGuard traffic through the
// encrypted frame channel over one or more WANs.
//
// Topology (docs/DESIGN.md §3.1, co-located egress):
//
//	[WG client] ──► ingress socket ──► client: scheduler → per-WAN seal/send
//	    ──► (WAN 1..N) ──► server: recv+open ──► egress socket ──► [WG peer]
//
// M3: the client schedules each inner datagram onto one of N WANs (per-WAN
// FEC blocks), monitors every WAN with keepalive probes and a circuit
// breaker, and reassembles the server → client stream in-order via the
// delivery buffer. The server mirrors this per session: per-path health and
// per-block endpoint selection.
//
// Lifecycle: Start() binds all sockets and returns init errors synchronously
// (port busy, bad address); Run(ctx) then starts the goroutines and blocks.
// Socket fields are read-only after Start, so no locking is needed for them.
package tunnel

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ColinFL/flexbraid/internal/config"
	"github.com/ColinFL/flexbraid/internal/crypto"
	"github.com/ColinFL/flexbraid/internal/fec"
	"github.com/ColinFL/flexbraid/internal/frame"
	"github.com/ColinFL/flexbraid/internal/health"
	"github.com/ColinFL/flexbraid/internal/scheduler"
	"github.com/ColinFL/flexbraid/internal/session"
	"github.com/ColinFL/flexbraid/internal/transport"
)

const (
	// handshakeInterval is how often the client (re)sends its FIRST frame on
	// every WAN. This doubles as a lightweight NAT keepalive and guarantees
	// the server learns every path even if early packets are lost.
	handshakeInterval = 5 * time.Second
	// recvBufSize is the max UDP datagram size we accept.
	recvBufSize = 65535
	// defaultProbeInterval is the keepalive probe period when
	// health.probe_interval is unset.
	defaultProbeInterval = time.Second
	// defaultDegradeSec is the DEGRADED hysteresis window default.
	defaultDegradeSec = 3 * time.Second
	// maxWANs caps the number of WANs a client may configure.
	maxWANs = 16
)

func resolveUDPAddr(s string) (*net.UDPAddr, error) {
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", s, err)
	}
	return addr, nil
}

// wanLink is the per-WAN state of the client: transport, per-WAN FEC codecs
// (blocks never mix WANs), the health monitor and the keepalive probe state.
type wanLink struct {
	id     string
	cfg    config.WAN
	tr     transport.Transport
	enc    *fec.Encoder // client → server
	dec    *fec.Decoder // server → client
	health *health.Monitor

	// sendMu serializes batches on this WAN (P4): the ingress and FEC-tick
	// loops cannot interleave frames of one block with another.
	sendMu sync.Mutex

	// pathSeq is this WAN's monotonic counter for pass-through frames
	// (stamped into BlockSeq under sendMu in sendLocked). The receiver
	// derives raw per-path loss from gaps in it — the adaptive FEC trigger
	// (Variant A). Guarded by sendMu.
	pathSeq uint32

	// framesSent counts data frames handed to this WAN's transport
	// (telemetry + failover tests; keepalives excluded).
	framesSent atomic.Uint64
	// pongs / missedProbes count probe outcomes (telemetry + tests).
	pongs        atomic.Uint64
	missedProbes atomic.Uint64
	// lastRx is the unix-nano time of the last VALID frame received on
	// this WAN (any kind). Any traffic proves the path is alive, so a
	// delayed PONG on a busy path is not mistaken for loss (P3).
	lastRx atomic.Int64

	// Keepalive probe state (keepaliveLoop + recvLoop).
	probeMu    sync.Mutex
	probeOut   bool          // previous probe unanswered?
	probeRTT   time.Duration // RTT of the last answered probe
	probeStart time.Time     // when the outstanding probe was sent

	// q is the bounded send queue + token bucket (§7.6); nil disables it.
	q *sendQueue
}

// errQueueDropped reports that a frame could not be queued (overflow or the
// frame exceeding the queue bound).
var errQueueDropped = errors.New("send queue dropped frame")

// Client is the FlexBraid tunnel client (office side).
type Client struct {
	cfg      *config.Config
	log      *slog.Logger
	baseAEAD cipher.AEAD // handshake key (derived from PSK only)
	psk      []byte      // raw PSK (used to derive the PFS session key)
	sess     *session.Client
	wans     []*wanLink
	byWAN    map[string]*wanLink
	sched    *scheduler.Scheduler
	delivery *deliveryBuffer

	// PFS key exchange (M5.5): the client's ephemeral X25519 keypair is
	// generated at NewClient; the server's ephemeral public key arrives in
	// the KEX_ACK, and the negotiated session AEAD is published once under
	// sessMu. Locked so send/recv loops never observe a half-written key.
	sessMu       sync.RWMutex
	sessAEAD     cipher.AEAD // negotiated per-session key (nil until KEX_ACK)
	sessionReady bool        // true once sessAEAD is published
	clientPriv   []byte      // ephemeral X25519 private key (never leaves process)
	clientPub    []byte      // ephemeral X25519 public key (sent in KEX_REQ)

	probeInterval time.Duration

	// Cross-path FEC (fec.mode: crosspath): ONE codec shared by every WAN;
	// blocks are spread across all usable paths (scheduler.PickWRR) and the
	// decoder keys them by session only, so frames from different paths
	// assemble into the same block (docs/DESIGN.md §6.4). The FEC geometry
	// and inner MTU are SERVER-AUTHORITATIVE: the server announces them in
	// the KEX_ACK and the client rebuilds its codecs before the session key
	// is published, so every data frame uses the server's parameters
	// (config.ServerAnnounce).
	//
	// codecMu guards the codec slots (crossPath, xenc/xdec, per-WAN enc/dec)
	// and the effective MTU. Readers snapshot the pointers they need under
	// RLock and use them after; writers only ever REPLACE whole codec objects
	// (never mutate in place), so a reader that grabbed the previous codec
	// finishes that one frame/tick with it — the swap applies from the next.
	codecMu   sync.RWMutex
	crossPath bool
	xenc      *fec.Encoder
	xdec      *fec.Decoder
	// mtu is the effective inner MTU (atomic: read on the ingress hot path).
	// Initialized from cfg.MTU at NewClient, replaced by the server's value
	// on handshake. cfg.MTU stays as the config-file value for reload/log.
	mtu atomic.Int64
	// adoptedFEC is the FEC block the server announced and the codecs were
	// rebuilt from (zero unless/until a handshake adopted one). Logged so a
	// "session established" line reports the FEC actually in effect — the
	// client's own config no longer carries it (server-authoritative).
	adoptedFEC config.FEC

	// sendErrs throttles repeated send-failure logging (P6).
	sendErrs atomic.Uint64
	// oversizeErrs throttles MTU-exceeded logging (P6).
	oversizeErrs atomic.Uint64
	// noWANErrs throttles 'no usable WAN' logging.
	noWANErrs atomic.Uint64
	// preSessErrs throttles 'dropped before PFS established' logging.
	preSessErrs atomic.Uint64

	ingress *net.UDPConn // read-only after Start
	// start marks construction time (telemetry uptime).
	start time.Time
}

// pathMTU is the assumed WAN path MTU for the inner-MTU check. The largest
// frame on the wire is a parity frame: payload + FEC sub-header + frame
// header + AEAD tag, and it must fit the path MTU without IP fragmentation
// (a lost fragment would defeat FEC entirely — design §6.6).
const pathMTU = 1500

// newTransport builds the wire transport for a WAN: plain encrypted UDP or
// the FakeTCP disguise (raw IPv4/TCP segments, docs/DESIGN.md §8.2).
func newTransport(wcfg *config.WAN, serverAddr string) (transport.Transport, error) {
	bind := transport.Bind{Iface: wcfg.Iface, LocalIP: wcfg.LocalIP, FIB: wcfg.FIB}
	switch wcfg.Transport {
	case config.TransportFakeTCP:
		return transport.NewFakeTCP(wcfg.ID, "", serverAddr, bind), nil
	case config.TransportICMP:
		return transport.NewICMP(wcfg.ID, "", serverAddr, bind), nil
	case config.TransportUDP:
		return transport.NewUDP(wcfg.ID, "", serverAddr, bind), nil
	default:
		return nil, fmt.Errorf("wan %q: unsupported transport %q", wcfg.ID, wcfg.Transport)
	}
}

// fecParamsFor derives codec params for one WAN from the config, honouring a
// per-WAN max_loss override. A disabled or off-mode FEC yields pass-through
// codecs (no buffering, no parity).
func fecParamsFor(cfg *config.Config, wan *config.WAN) (fec.Params, error) {
	f := cfg.FEC
	timeout := time.Duration(f.BlockTimeoutMS) * time.Millisecond
	if !f.Enabled || f.Mode == config.FECOff {
		return fec.Params{BlockTimeout: timeout}, nil
	}
	if f.Mode == config.FECCrosspath {
		// Cross-path FEC (docs/DESIGN.md §6.4): one codec shared by all
		// WANs, blocks spread across every usable path, so a whole-WAN
		// failure loses only its share of each block — recoverable when
		// the redundancy covers it. Parity is floored by protection_level
		// (coding is always ON: pass-through would make a WAN loss
		// unrecoverable) and may grow with measured loss on top.
		k := fec.DefaultDataShards
		if f.DataShards > 0 {
			k = f.DataShards
		}
		minParity := int(math.Ceil(float64(k) * f.ProtectionLevel))
		if minParity < 1 {
			minParity = 1
		}
		return fec.Params{
			DataShards:         k,
			ParityShards:       minParity,
			BlockTimeout:       timeout,
			CrossPath:          true,
			CrossPathMinParity: minParity,
		}, nil
	}
	k := fec.DefaultDataShards
	if f.DataShards > 0 {
		k = f.DataShards
	}
	var parity int
	var adaptive *fec.AdaptiveParams
	switch f.Mode {
	case config.FECFixed:
		parity = int(math.Ceil(float64(k) * f.FixedOverheadPct / 100.0))
	case config.FECAdaptive:
		// The configured max_loss_pct is the REDUNDANCY CEILING; the
		// encoder sizes actual parity on the fly from the measured loss
		// (fec.Params.Adaptive + Encoder.SetLossRate). On a clean link it
		// codes nothing at all — zero latency, zero overhead.
		l := f.MaxLossPct / 100.0
		if wan != nil && wan.FECMaxLossPct != nil {
			l = *wan.FECMaxLossPct / 100.0
		}
		if l <= 0 || l >= 1 {
			return fec.Params{}, fmt.Errorf("invalid fec max_loss_pct %v (must be 0 < x < 100)", l*100)
		}
		parity = int(math.Ceil(float64(k) * l / (1 - l)))
		adaptive = &fec.AdaptiveParams{
			OnLossPct:  f.AdaptMinLossPct,
			OffLossPct: f.AdaptResumePct,
			Hold:       time.Duration(f.AdaptHoldSec * float64(time.Second)),
			MaxLossPct: f.MaxLossPct,
			Safety:     1.3,
		}
	default:
		return fec.Params{}, fmt.Errorf("unknown fec.mode %q", f.Mode)
	}
	if parity < 1 {
		parity = 1
	}
	// Reed–Solomon field bound: klauspost/reedsolomon supports at most
	// 256 shards per block. A large k combined with a high max_loss_pct
	// can exceed it; fail fast with the exact constraint.
	if k+parity > 256 {
		return fec.Params{}, fmt.Errorf("fec geometry too large: k=%d + parity=%d > 256 (reduce data_shards or max_loss_pct)", k, parity)
	}
	params := fec.Params{DataShards: k, ParityShards: parity, BlockTimeout: timeout, Adaptive: adaptive}
	// P2: the largest parity frame must fit the path MTU without IP
	// fragmentation. Fail fast with the exact bound instead of silently
	// fragmenting (or dropping) parity frames.
	if maxInner := pathMTU - frame.HeaderSize - frame.TagSize - fec.ParityHeaderSize(k); cfg.MTU > maxInner {
		return fec.Params{}, fmt.Errorf(
			"inner mtu %d too large with FEC(k=%d): parity frames need %d bytes of headroom on %d-byte paths; set mtu <= %d or disable FEC",
			cfg.MTU, k, frame.HeaderSize+frame.TagSize+fec.ParityHeaderSize(k), pathMTU, maxInner)
	}
	return params, nil
}

// fecCompensableLoss returns the loss fraction the configured FEC can repair
// (0 when disabled) — the health monitor's degrade threshold.
func fecCompensableLoss(p fec.Params) float64 {
	if !p.Enabled() {
		// No FEC means no compensable loss, period. The caller maps this
		// to a tiny EWMA noise floor so the state machine stays sane.
		return 0
	}
	return float64(p.ParityShards) / float64(p.DataShards+p.ParityShards)
}

// effectiveCapacity returns a path's scheduling weight for balance_by:
// declared capacity, reduced by the per-path FEC overhead, or 1 for
// round-robin.
func effectiveCapacity(wan config.WAN, p fec.Params, balanceBy config.BalanceBy) float64 {
	if balanceBy == config.BalanceByRoundRobin {
		return 1
	}
	cap := float64(wan.CapacityMbps)
	if cap <= 0 {
		cap = 1 // unknown capacity: assume equal share
	}
	if balanceBy == config.BalanceByFEC && p.Enabled() {
		overhead := float64(p.ParityShards) / float64(p.DataShards+p.ParityShards)
		cap *= 1 - overhead
	}
	if wan.Weight > 0 {
		cap *= wan.Weight
	}
	return cap
}

// monitorMaxLoss maps FEC capacity onto the health monitor's degrade
// threshold. No FEC → 0 compensable loss, expressed as a 1% EWMA noise
// floor so the state machine keeps working (a strict 0 would make the
// recovery condition unreachable).
func monitorMaxLoss(p fec.Params) float64 {
	if l := fecCompensableLoss(p); l > 0 {
		return l
	}
	return 0.01
}

// healthOptions maps the config's health section onto monitor options.
func healthOptions(h config.Health, maxLoss float64, probeInterval time.Duration) health.Options {
	return health.Options{
		MaxLoss:         maxLoss,
		DegradeAfter:    time.Duration(h.DegradeSec * float64(time.Second)),
		RecoverAfter:    time.Duration(h.RecoverMin * float64(time.Minute)),
		LossAlphaFast:   h.LossAlphaFast,
		LossAlphaSlow:   h.LossAlphaSlow,
		JitterAlpha:     h.JitterAlpha,
		DownAfterMisses: h.DownAfterMisses,
		DownGrace:       time.Duration(h.DownGraceSec * float64(time.Second)),
	}
}

// NewClient builds a tunnel client from config.
func NewClient(cfg *config.Config, log *slog.Logger) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(cfg.WANs) == 0 {
		return nil, fmt.Errorf("client requires at least one WAN")
	}
	if len(cfg.WANs) > maxWANs {
		return nil, fmt.Errorf("too many WANs: %d (max %d)", len(cfg.WANs), maxWANs)
	}
	for i := range cfg.WANs {
		if cfg.WANs[i].Transport == "" {
			cfg.WANs[i].Transport = config.TransportUDP
		}
		if cfg.WANs[i].ID == "" {
			return nil, fmt.Errorf("wan[%d].id is required", i)
		}
	}

	baseKey, err := crypto.DeriveKey([]byte(cfg.Crypto.Key))
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	baseAEAD, err := crypto.NewAEAD(baseKey, cfg.Crypto.Cipher)
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}

	// The session ID is chosen before the session key exists; the key is
	// negotiated later via X25519 PFS (M5.5) from the client's ephemeral
	// keypair + the server's ephemeral key in the KEX_ACK.
	id, err := session.NewID()
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	clientPriv, clientPub, err := crypto.GenerateEphemeralKey()
	if err != nil {
		return nil, fmt.Errorf("pfs keypair: %w", err)
	}

	probeInterval := time.Duration(cfg.Health.ProbeInterval * float64(time.Second))
	if probeInterval <= 0 {
		probeInterval = defaultProbeInterval
	}
	c := &Client{
		cfg:           cfg,
		log:           log,
		baseAEAD:      baseAEAD,
		psk:           []byte(cfg.Crypto.Key),
		sess:          session.NewClientWithID(id),
		byWAN:         make(map[string]*wanLink),
		sched:         scheduler.New(schedulerOptions(cfg)),
		probeInterval: probeInterval,
		clientPriv:    clientPriv,
		clientPub:     clientPub,
		start:         time.Now(),
	}
	c.mtu.Store(int64(cfg.MTU))
	// Cross-path FEC shares one codec across all WANs (blocks span every
	// path; per-WAN codecs would never see a full block). Per-WAN FEC
	// (adaptive/fixed) keeps one codec per WAN.
	if cfg.FEC.Mode == config.FECCrosspath {
		c.crossPath = true
		xparams, err := fecParamsFor(cfg, &cfg.WANs[0]) // wan-independent in cross-path mode
		if err != nil {
			return nil, err
		}
		if c.xenc, err = fec.NewEncoder(xparams); err != nil {
			return nil, fmt.Errorf("cross-path fec encoder: %w", err)
		}
		if c.xdec, err = fec.NewDecoder(xparams); err != nil {
			return nil, fmt.Errorf("cross-path fec decoder: %w", err)
		}
	}
	// Per-WAN transports, FEC codecs and health monitors.
	queueDrop, _ := parseQueueDrop(cfg.Queue.Drop) // validated already
	queueEnabled := cfg.Queue.Enabled != nil && *cfg.Queue.Enabled
	for i := range cfg.WANs {
		wcfg := &cfg.WANs[i]
		params, err := fecParamsFor(cfg, wcfg)
		if err != nil {
			return nil, err
		}
		enc, dec := (*fec.Encoder)(nil), (*fec.Decoder)(nil)
		if c.crossPath {
			enc, dec = c.xenc, c.xdec
		} else {
			if enc, err = fec.NewEncoder(params); err != nil {
				return nil, fmt.Errorf("wan %s fec encoder: %w", wcfg.ID, err)
			}
			if dec, err = fec.NewDecoder(params); err != nil {
				return nil, fmt.Errorf("wan %s fec decoder: %w", wcfg.ID, err)
			}
		}
		mon := health.New(healthOptions(cfg.Health, fecCompensableLoss(params), probeInterval))
		tr, err := newTransport(wcfg, cfg.Server)
		if err != nil {
			return nil, err
		}
		// Per-WAN bounded send queue + token bucket (§7.6). The rate is
		// the declared capacity in bytes/second (Mbps → MB/s → B/s); the
		// bucket holds one queue-worth of burst so short bursts ride out
		// on FEC blocks without artificial pacing.
		var q *sendQueue
		if queueEnabled {
			rateBps := 0.0
			if cfg.Queue.RateLimit {
				rateBps = float64(wcfg.CapacityMbps) * 1_000_000 / 8
			}
			q = newSendQueue(cfg.Queue.MaxBytes, queueDrop, rateBps)
		}
		wan := &wanLink{
			id:     wcfg.ID,
			cfg:    *wcfg,
			tr:     tr,
			enc:    enc,
			dec:    dec,
			health: mon,
			q:      q,
		}
		c.wans = append(c.wans, wan)
		c.byWAN[wcfg.ID] = wan
		c.sched.AddPath(wcfg.ID, effectiveCapacity(*wcfg, params, cfg.Scheduler.BalanceBy))
		log.Info("wan configured",
			"wan", wcfg.ID,
			"transport", wcfg.Transport,
			"capacity_mbps", wcfg.CapacityMbps,
			"fec", fecSummary(params),
			"queue", queueEnabled)
	}
	// Delivery buffer: gap timeout covers FEC block assembly + path RTT
	// skew (configurable; 100ms default for mixed cable+LTE uplinks).
	c.delivery = newDeliveryBuffer(
		time.Duration(cfg.Delivery.GapTimeoutMS)*time.Millisecond,
		cfg.Delivery.MaxPending,
	)
	return c, nil
}

func fecSummary(p fec.Params) string {
	if !p.Enabled() {
		return "off"
	}
	return fmt.Sprintf("k=%d parity=%d", p.DataShards, p.ParityShards)
}

func schedulerOptions(cfg *config.Config) scheduler.Options {
	return scheduler.Options{
		Mode:      string(cfg.Scheduler.Mode),
		Affinity:  string(cfg.Scheduler.Affinity),
		BalanceBy: string(cfg.Scheduler.BalanceBy),
	}
}

// Start binds the ingress socket and opens all WAN transports. It must be
// called before Run and returns init errors (e.g. port busy) synchronously.
func (c *Client) Start() error {
	ingressAddr, err := resolveUDPAddr(c.cfg.Listen)
	if err != nil {
		return fmt.Errorf("ingress address: %w", err)
	}
	ingress, err := net.ListenUDP("udp", ingressAddr)
	if err != nil {
		return fmt.Errorf("ingress listen %s: %w", c.cfg.Listen, err)
	}
	c.ingress = ingress

	for _, wan := range c.wans {
		if err := wan.tr.Open(); err != nil {
			ingress.Close()
			for _, w := range c.wans {
				w.tr.Close()
			}
			return fmt.Errorf("wan %s: %w", wan.id, err)
		}
	}
	return nil
}

// Run starts the client loops and blocks until ctx is cancelled. Call Start
// first.
func (c *Client) Run(ctx context.Context) error {
	defer c.ingress.Close()
	defer func() {
		for _, wan := range c.wans {
			wan.tr.Close()
		}
	}()

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Unblock the blocking loops on shutdown: ingressLoop sits in
	// ReadFromUDP and recvLoops in tr.Recv(), and neither returns while
	// its socket is open — so the sockets must be closed the moment the
	// context dies, not after the loops return (that would deadlock).
	go func() {
		<-ctx.Done()
		c.ingress.Close()
		for _, wan := range c.wans {
			wan.tr.Close()
		}
	}()

	// One handshake + keepalive + recv loop per WAN.
	var recvWG sync.WaitGroup
	for _, wan := range c.wans {
		if wan.q != nil {
			// Queue consumer: drains the bounded FIFO and paces writes to
			// the WAN's capacity (§7.6). Stops with ctx.
			go wan.q.run(ctx, wan.tr.Send, c.log)
		}
		go c.handshakeLoop(ctx, wan)
		go c.keepaliveLoop(ctx, wan)
		recvWG.Add(1)
		go func(w *wanLink) {
			defer recvWG.Done()
			c.recvLoop(w)
		}(wan)
	}
	go c.fecTickLoop(ctx)
	go c.healthTickLoop(ctx)

	wans := make([]string, len(c.wans))
	for i, wan := range c.wans {
		wans[i] = wan.id
	}
	c.log.Info("client started",
		"session", fmt.Sprintf("%016x", uint64(c.sess.ID)),
		"ingress", c.cfg.Listen,
		"server", c.cfg.Server,
		"wans", wans,
		"scheduler", c.cfg.Scheduler.Mode,
		"affinity", c.cfg.Scheduler.Affinity)

	err := c.ingressLoop(ctx)
	// Loops may still be blocked if the goroutine above hasn't run yet;
	// close again (idempotent) to guarantee they unblock before Wait.
	c.ingress.Close()
	for _, wan := range c.wans {
		wan.tr.Close()
	}
	recvWG.Wait()
	return err
}

// LocalAddr returns the client's ingress address (valid after Start).
func (c *Client) LocalAddr() *net.UDPAddr {
	if c.ingress == nil {
		return nil
	}
	return c.ingress.LocalAddr().(*net.UDPAddr)
}

// handshakeLoop sends the FIRST/KEX_REQ frame immediately and then every
// handshakeInterval, on one WAN. FIRST frames are sealed with the *base*
// key — the server has no session yet, so it cannot know the per-session
// key. The payload carries the WAN's declared capacity (so the server can
// weight its own per-path scheduling) followed by the client's ephemeral
// X25519 public key (M5.5 PFS).
func (c *Client) handshakeLoop(ctx context.Context, wan *wanLink) {
	send := func() {
		payload := make([]byte, 4+crypto.PublicKeySize)
		binary.BigEndian.PutUint32(payload, uint32(wan.cfg.CapacityMbps))
		copy(payload[4:], c.clientPub)
		f := &frame.Frame{
			Flags:     frame.FlagFirst, // KEX_REQ
			SessionID: uint64(c.sess.ID),
			Seq:       c.sess.NextSeq(),
			Payload:   payload,
		}
		if err := c.send(wan, f, c.baseAEAD); err != nil {
			c.log.Warn("handshake send failed", "wan", wan.id, "error", err)
		}
	}
	send()
	t := time.NewTicker(handshakeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			send()
		}
	}
}

// keepaliveLoop probes one WAN every probeInterval with a KEEPALIVE frame;
// the server answers with a PONG carrying the same timestamp, giving the
// client a per-WAN loss + RTT sample.
//
// A probe counts as MISSED only when the path is otherwise silent: if any
// valid frame (data or control) arrived on this WAN since the probe was
// sent, the path is alive and the PONG is merely delayed (jitter under
// load) — marking it lost would false-trip the circuit breaker on a busy
// link and stall traffic (P3).
func (c *Client) keepaliveLoop(ctx context.Context, wan *wanLink) {
	send := func() {
		aead, ok := c.getSessionAEAD()
		if !ok {
			return // PFS session not established yet; skip the probe
		}
		payload := make([]byte, 8)
		binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixMilli()))
		f := &frame.Frame{
			Flags:     frame.FlagKeepalive,
			SessionID: uint64(c.sess.ID),
			Seq:       c.sess.NextSeq(),
			Payload:   payload,
		}
		if err := c.send(wan, f, aead); err != nil {
			c.log.Warn("keepalive send failed", "wan", wan.id, "error", err)
		}
		wan.probeMu.Lock()
		wan.probeOut = true
		wan.probeStart = time.Now()
		wan.probeMu.Unlock()
	}
	send()
	t := time.NewTicker(c.probeInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			wan.probeMu.Lock()
			wasOut := wan.probeOut
			rtt := wan.probeRTT
			wan.probeMu.Unlock()
			if wasOut {
				sinceRx := time.Since(time.Unix(0, wan.lastRx.Load()))
				if sinceRx > 2*c.probeInterval {
					// No frame at all on this path since the probe: a real
					// loss sample.
					wan.health.NoteMissedProbe()
					wan.health.ObserveSample(1, 0)
					wan.missedProbes.Add(1)
				} else {
					// Traffic is flowing; the PONG is just late.
					wan.health.ObserveSample(0, 0)
				}
			} else {
				wan.health.ObserveSample(0, rtt)
			}
			send()
		}
	}
}

// handlePong processes a PONG reply on one WAN: it echoes the probe's
// timestamp, so RTT = now − ts. The loss sample is booked by the keepalive
// loop at the next tick.
func (c *Client) handlePong(wan *wanLink, f *frame.Frame) {
	if len(f.Payload) != 8 {
		return
	}
	ts := int64(binary.BigEndian.Uint64(f.Payload))
	wan.probeMu.Lock()
	wan.probeRTT = time.Since(time.UnixMilli(ts))
	wan.probeOut = false
	wan.probeMu.Unlock()
	wan.pongs.Add(1)
}

// getSessionAEAD returns the negotiated PFS session cipher, or ok=false
// before the key exchange completes.
func (c *Client) getSessionAEAD() (cipher.AEAD, bool) {
	c.sessMu.RLock()
	defer c.sessMu.RUnlock()
	return c.sessAEAD, c.sessionReady
}

// setSessionAEAD publishes the negotiated session cipher exactly once.
func (c *Client) setSessionAEAD(a cipher.AEAD) {
	c.sessMu.Lock()
	defer c.sessMu.Unlock()
	if c.sessionReady {
		return
	}
	c.sessAEAD = a
	c.sessionReady = true
}

// handleKexAck processes the server's key-exchange ACK (M5.5): it carries
// the server's ephemeral X25519 public key sealed under the base (PSK) key,
// followed by the server's authoritative FEC/MTU announce. The client
// derives the forward-secret session key, rebuilds its codecs from the
// announced parameters (so both ends code identically), and only then
// publishes the session key — no data frame can pass the PFS gate until the
// codecs match the server's. Returns true if the ACK authenticated.
func (c *Client) handleKexAck(sealed []byte) bool {
	plain, err := crypto.Open(c.baseAEAD, crypto.DirServerToClient, sealed)
	if err != nil {
		return false
	}
	f, err := frame.Decode(plain)
	if err != nil || f.SessionID != uint64(c.sess.ID) {
		return false
	}
	if len(f.Payload) < crypto.PublicKeySize {
		return false
	}
	if _, ready := c.getSessionAEAD(); ready {
		return true // already established; duplicate ACK
	}
	shared, err := crypto.ECDHShared(c.clientPriv, f.Payload[:crypto.PublicKeySize])
	if err != nil {
		return false
	}
	key := crypto.DerivePFSKey(c.psk, shared, uint64(c.sess.ID))
	aead, err := crypto.NewAEAD(key, c.cfg.Crypto.Cipher)
	if err != nil {
		return false
	}
	// Rebuild FEC codecs + effective MTU from the server's announce BEFORE
	// publishing the session key. A bad/missing announce aborts the handshake
	// (the client keeps re-sending FIRST until a valid ACK arrives) rather
	// than risking a codec mismatch for the whole session.
	if err := c.applyAnnounce(f.Payload[crypto.PublicKeySize:]); err != nil {
		c.log.Warn("rejecting server parameters",
			"session", fmt.Sprintf("%016x", uint64(c.sess.ID)), "error", err)
		return false
	}
	c.setSessionAEAD(aead)
	// Report the FEC actually in effect: the server's announced values now
	// drive the codecs. c.cfg.FEC is empty on a server-push client, so fall
	// back to it (single-WAN/local setups) only when nothing was adopted.
	c.codecMu.RLock()
	fecMode := c.cfg.FEC.Mode
	if c.adoptedFEC.Mode != "" {
		fecMode = c.adoptedFEC.Mode
	}
	c.codecMu.RUnlock()
	c.log.Info("session established",
		"session", fmt.Sprintf("%016x", uint64(c.sess.ID)),
		"key_exchange", "x25519-pfs",
		"fec_mode", fecMode,
		"mtu", c.mtu.Load())
	return true
}

// applyAnnounce adopts the server's authoritative FEC + inner MTU: it
// rebuilds every codec slot from the announced parameters under codecMu.
// The geometry must be byte-identical to the server's own, which is exactly
// what the server pushes (it marshals the same validated config its codecs
// were built from). Per-WAN fec_max_loss_pct overrides from the client's
// own WAN entries survive: they only size the client's encoder capacity —
// parity is self-describing, so the server's decoder does not need them.
// Returns an error for a malformed announce, an unknown version, or a
// geometry the validated config would refuse; the caller aborts the
// handshake rather than start the session on mismatched codecs.
func (c *Client) applyAnnounce(data []byte) error {
	var ann config.ServerAnnounce
	if len(data) == 0 {
		return fmt.Errorf("server sent no parameters block (server too old?)")
	}
	if err := json.Unmarshal(data, &ann); err != nil {
		return fmt.Errorf("malformed server parameters: %w", err)
	}
	if ann.Version != config.AnnounceVersion {
		return fmt.Errorf("unsupported server parameters version %d (this client speaks v%d)",
			ann.Version, config.AnnounceVersion)
	}
	// Normalize the announced FEC with the same defaults Validate applies:
	// a server that predates the max_loss_pct default (or a hand-edited
	// announce) with adaptive mode must not kill the client's handshake.
	annFEC := ann.FEC
	if annFEC.Enabled && annFEC.MaxLossPct == 0 {
		annFEC.MaxLossPct = config.DefaultMaxLossPct
	}
	// Feasibility check: re-derive the codec params exactly as the server
	// would (same function fecParamsFor). A temp config carries only the
	// announced FEC + MTU; cfg.Validate's MTU range is folded into
	// fecParamsFor's own checks.
	tmp := &config.Config{FEC: annFEC, MTU: ann.MTU}
	c.codecMu.Lock()
	defer c.codecMu.Unlock()

	c.crossPath = annFEC.Mode == config.FECCrosspath
	if c.crossPath {
		// One shared codec across all WANs (wan-independent).
		p, err := fecParamsFor(tmp, nil)
		if err != nil {
			return fmt.Errorf("server FEC parameters invalid: %w", err)
		}
		if c.xenc, err = fec.NewEncoder(p); err != nil {
			return fmt.Errorf("adopt server cross-path FEC: %w", err)
		}
		if c.xdec, err = fec.NewDecoder(p); err != nil {
			return fmt.Errorf("adopt server cross-path FEC: %w", err)
		}
	} else {
		// Per-WAN codecs (adaptive/fixed/off), one per WAN.
		for i, wan := range c.wans {
			p, err := fecParamsFor(tmp, &c.cfg.WANs[i])
			if err != nil {
				return fmt.Errorf("server FEC parameters invalid: %w", err)
			}
			wan.enc, err = fec.NewEncoder(p)
			if err != nil {
				return fmt.Errorf("adopt server FEC for %s: %w", wan.id, err)
			}
			wan.dec, err = fec.NewDecoder(p)
			if err != nil {
				return fmt.Errorf("adopt server FEC for %s: %w", wan.id, err)
			}
		}
	}
	c.mtu.Store(int64(ann.MTU))
	c.adoptedFEC = annFEC
	c.log.Info("adopted server parameters",
		"fec_enabled", annFEC.Enabled,
		"fec_mode", annFEC.Mode,
		"data_shards", annFEC.DataShards,
		"mtu", ann.MTU)
	return nil
}

// send seals and transmits one frame on a WAN. P4: the WAN's sendMu is held
// for the whole call so a control frame cannot interleave with a data batch.
func (c *Client) send(wan *wanLink, f *frame.Frame, aead cipher.AEAD) error {
	wan.sendMu.Lock()
	defer wan.sendMu.Unlock()
	return c.sendLocked(wan, f, aead)
}

// sendLocked seals and transmits one frame on a WAN. P4: the call holds the
// WAN's sendMu (caller-acquired). Pass-through frames (FlagPassSeq) get this
// path's monotonic counter stamped into BlockSeq before sealing: the
// receiver derives raw per-path loss from gaps in that counter. sendMu
// serializes the increments so the sequence is exact per WAN.
func (c *Client) sendLocked(wan *wanLink, f *frame.Frame, aead cipher.AEAD) error {
	if aead == nil {
		return nil // PFS session not established yet — drop (WG retransmits)
	}
	if f.HasFlag(frame.FlagPassSeq) {
		f.BlockSeq = wan.pathSeq
		wan.pathSeq++
	}
	plain, err := f.Encode()
	if err != nil {
		return err
	}
	sealed, err := crypto.Seal(aead, crypto.DirClientToServer, plain)
	if err != nil {
		return err
	}
	if wan.q != nil {
		// Bounded queue (§7.6): non-blocking; overflow applies the drop
		// policy. The consumer goroutine owns the actual transport write.
		if !wan.q.enqueue(sealed) {
			return errQueueDropped
		}
		return nil
	}
	return wan.tr.Send(sealed)
}

// sendEncoded seals and transmits one FEC block on its WAN. Data frames
// already carry their seq (assigned before Push, so the parity sub-header
// records the true seqs); parity frames get a fresh seq here. The whole
// block is sent under one hold of the WAN's sendMu (P4).
func (c *Client) sendEncoded(wan *wanLink, frames []*frame.Frame) {
	aead, ok := c.getSessionAEAD()
	if !ok {
		return // PFS session not established yet — drop the batch
	}
	wan.sendMu.Lock()
	defer wan.sendMu.Unlock()
	for _, f := range frames {
		if f.HasFlag(frame.FlagFECParity) {
			f.Seq = c.sess.NextSeq()
		}
		wan.framesSent.Add(1)
		if err := c.sendLocked(wan, f, aead); err != nil {
			c.noteSendErr(err)
		}
	}
}

// sendCrossEncoded spreads one cross-path block over all usable WANs
// (smooth WRR): a whole-WAN failure then costs only its share of each
// block — recoverable when the cross-path parity covers it. Unlike
// sendEncoded there is no single sendMu: each frame takes its own WAN's
// lock, so frames of one block leave concurrently over different links.
func (c *Client) sendCrossEncoded(frames []*frame.Frame) {
	aead, ok := c.getSessionAEAD()
	if !ok {
		return // PFS session not established yet — drop the batch
	}
	for _, f := range frames {
		if f.HasFlag(frame.FlagFECParity) {
			f.Seq = c.sess.NextSeq()
		}
		wanID, ok := c.sched.PickWRR()
		if !ok {
			c.noteNoWAN()
			continue
		}
		wan := c.byWAN[wanID]
		wan.sendMu.Lock()
		c.sendLocked(wan, f, aead)
		wan.sendMu.Unlock()
	}
}

// noteSendErr throttles repeated send-failure logging (P6): warn on the
// first failure, then every 100th.
func (c *Client) noteSendErr(err error) {
	n := c.sendErrs.Add(1)
	if n == 1 || n%100 == 0 {
		c.log.Warn("send failures", "count", n, "last_error", err)
	}
}

// noteOversize logs dropped inner datagrams that exceed the configured MTU,
// throttled like send errors (P6).
func (c *Client) noteOversize(n int) {
	m := c.oversizeErrs.Add(1)
	if m == 1 || m%100 == 0 {
		c.log.Warn("dropped oversize inner datagram (mtu exceeded)",
			"bytes", n, "mtu", c.mtu.Load(), "count", m)
	}
}

// noteNoWAN logs frames dropped because every WAN is down, throttled.
func (c *Client) noteNoWAN() {
	n := c.noWANErrs.Add(1)
	if n == 1 || n%1000 == 0 {
		c.log.Warn("no usable WAN, dropping inner datagram", "count", n)
	}
}

// notePreSession logs inner datagrams dropped before the PFS key exchange
// completes, throttled (M5.5; WireGuard retransmits).
func (c *Client) notePreSession() {
	n := c.preSessErrs.Add(1)
	if n == 1 || n%1000 == 0 {
		c.log.Info("dropping inner datagram before PFS session established", "count", n)
	}
}

// ingressLoop relays inner datagrams (WireGuard) into the tunnel, picking a
// WAN per datagram via the scheduler.
func (c *Client) ingressLoop(ctx context.Context) error {
	buf := make([]byte, recvBufSize)
	for {
		n, addr, err := c.ingress.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("ingress read: %w", err)
		}
		// Roaming: the inner WireGuard peer may change its source
		// address (NAT rebind, Wi-Fi→LTE switch on the LAN side, WG
		// restart). Always adopt the latest authenticated source — it
		// is the address replies must go to.
		if prev := c.sess.WGAddr(); prev == nil || prev.String() != addr.String() {
			if prev != nil {
				c.log.Info("inner peer address changed (roaming)",
					"old", prev.String(), "new", addr.String())
			}
			c.sess.SetWGAddr(addr)
		}
		// Defense-in-depth: the effective MTU (server-adopted after the
		// handshake) bounds the frame; drop anything larger than it instead
		// of letting an oversized frame hit the WAN.
		if n > int(c.mtu.Load()) {
			c.noteOversize(n)
			continue
		}
		// PFS gate (M5.5): until the key exchange completes, the peer
		// cannot decrypt anything — drop the datagram; WireGuard will
		// retransmit it once the tunnel is up.
		if _, ok := c.getSessionAEAD(); !ok {
			c.notePreSession()
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		f := &frame.Frame{
			SessionID: uint64(c.sess.ID),
			Seq:       c.sess.NextSeq(), // before Push: sub-header records true seqs
			Payload:   payload,
		}
		// Snapshot the codec slots under codecMu. The swap on handshake only
		// replaces whole codec objects, so finishing this frame on the
		// previous codec is safe — everything after the swap uses the
		// server's geometry.
		c.codecMu.RLock()
		crossPath := c.crossPath
		xenc := c.xenc
		c.codecMu.RUnlock()
		if crossPath {
			// Cross-path FEC: code the block globally, then spread its
			// frames over every usable WAN (smooth WRR). Blocks are keyed
			// by session on the receiver, so the WAN a frame travelled is
			// irrelevant to reassembly — only the surviving share matters.
			if frames := xenc.Push(f); len(frames) > 0 {
				c.sendCrossEncoded(frames)
			}
			continue
		}
		wanID, ok := c.sched.Pick(f)
		if !ok {
			c.noteNoWAN()
			continue
		}
		wan := c.byWAN[wanID]
		c.codecMu.RLock()
		enc := wan.enc
		c.codecMu.RUnlock()
		c.sendEncoded(wan, enc.Push(f))
	}
}

// recvLoop reads one WAN's sealed frames, verifies them, and routes them:
// PONGs feed the health monitor, KEX pulses complete the PFS handshake,
// everything else goes through the WAN's FEC decoder into the in-order
// delivery buffer.
func (c *Client) recvLoop(wan *wanLink) {
	for {
		sealed, _, err := wan.tr.Recv()
		if err != nil {
			return // transport closed
		}
		hdr, err := frame.DecodeHeader(sealed)
		if err != nil {
			continue
		}
		if hdr.SessionID == uint64(c.sess.ID) && hdr.HasFlag(frame.FlagKex) {
			// Server's PFS key-exchange ACK (sealed under the base key).
			if c.handleKexAck(sealed) {
				wan.lastRx.Store(time.Now().UnixNano())
			}
			continue
		}
		f, ok := c.openAndVerify(sealed)
		if !ok {
			continue
		}
		// Any valid frame proves the path is alive (liveness signal for
		// the circuit breaker; keeps delayed-PONG false trips at bay).
		wan.lastRx.Store(time.Now().UnixNano())
		if f.HasFlag(frame.FlagPong) {
			c.handlePong(wan, f)
			continue
		}
		// Control/keepalive frames carry no inner data.
		if f.HasFlag(frame.FlagControl) || f.HasFlag(frame.FlagKeepalive) || len(f.Payload) == 0 {
			continue
		}
		c.codecMu.RLock()
		dec := wan.dec
		c.codecMu.RUnlock()
		c.deliverToWG(c.delivery.Push(dec.Push(wan.id, f)))
	}
}

// deliverToWG writes decoded inner datagrams to the inner WireGuard peer.
func (c *Client) deliverToWG(frames []*frame.Frame) {
	addr := c.sess.WGAddr()
	if addr == nil {
		return // no inner peer yet
	}
	for _, f := range frames {
		if _, err := c.ingress.WriteToUDP(f.Payload, addr); err != nil {
			c.log.Warn("egress to inner peer failed", "error", err)
		}
	}
}

// fecTickInterval picks the FEC/delivery tick period. With FEC enabled it
// tracks half the block timeout so short blocks are flushed promptly. With
// FEC disabled the codecs are pass-through (BlockTimeout 0) — at that point
// the tick still advances the delivery buffer's gap timer, so it is paced
// off the gap timeout (1/4 of it) instead of spinning at 1 ms, which burned
// ~5% of an idle core (measured: 0.578s CPU/10s with FEC off vs 0.312s FEC
// on, on a small VM). Re-evaluated on every tick so adopting server FEC
// parameters (or a reload) tightens/loosens the cadence automatically.
func (c *Client) fecTickInterval() time.Duration {
	c.codecMu.RLock()
	defer c.codecMu.RUnlock()
	var bt time.Duration
	if c.crossPath {
		if c.xenc != nil {
			bt = c.xenc.Params().BlockTimeout
		}
	} else if len(c.wans) > 0 && c.wans[0].enc != nil {
		bt = c.wans[0].enc.Params().BlockTimeout
	}
	interval := bt / 2
	if interval < time.Millisecond {
		// FEC off (or a sub-1ms block timeout): pace off the delivery gap
		// timer, which this loop also drives. 1/4 gives it plenty of
		// granularity without a busy tick.
		gap := time.Duration(c.cfg.Delivery.GapTimeoutMS/4) * time.Millisecond
		if gap > interval {
			interval = gap
		}
	}
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	return interval
}

// fecTickLoop flushes short FEC blocks on every WAN (both directions) and
// advances the delivery buffer's gap timer.
func (c *Client) fecTickLoop(ctx context.Context) {
	interval := c.fecTickInterval()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			c.codecMu.RLock()
			crossPath := c.crossPath
			xenc, xdec := c.xenc, c.xdec
			c.codecMu.RUnlock()
			if crossPath {
				// One shared codec: single flush for encoder and decoder.
				c.sendCrossEncoded(xenc.Tick(now))
				c.deliverToWG(c.delivery.Push(xdec.Tick(now)))
			} else {
				for _, wan := range c.wans {
					c.codecMu.RLock()
					enc, dec := wan.enc, wan.dec
					c.codecMu.RUnlock()
					c.sendEncoded(wan, enc.Tick(now))
					c.deliverToWG(c.delivery.Push(dec.Tick(now)))
				}
				c.deliverToWG(c.delivery.Tick(now))
			}
			// Re-evaluate the cadence (server announce / reload may have
			// changed the codecs since).
			if next := c.fecTickInterval(); next != interval {
				interval = next
				t.Reset(next)
			}
		}
	}
}

// healthTickLoop advances every WAN's circuit breaker and pushes state
// changes into the scheduler, which is what actually removes a bad path from
// rotation (or restores it after recovery). In-band loss samples from each
// WAN's FEC decoder feed the monitors alongside the keepalive probes.
func (c *Client) healthTickLoop(ctx context.Context) {
	t := time.NewTicker(200 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			for _, wan := range c.wans {
				c.codecMu.RLock()
				enc, dec := wan.enc, wan.dec
				c.codecMu.RUnlock()
				// In-band signal: unrecovered loss on this path, measured
				// from real traffic. Instant under load — no probe latency.
				if lost, received := dec.TakeStreamStats(uint64(c.sess.ID), wan.id); received > 0 {
					rate := float64(lost) / float64(lost+received)
					if rate > 0 {
						wan.health.ObserveInBand(rate)
					}
				}
				// Raw per-path loss from pass-through frame counters:
				// the adaptive trigger that works under sustained load
				// (probes are suppressed by traffic there). Feeds the
				// loss EWMA without tripping the breaker.
				if rawLost, rawRecv := dec.TakePathStats(uint64(c.sess.ID), wan.id); rawRecv > 0 {
					if rate := float64(rawLost) / float64(rawLost+rawRecv); rate > 0 {
						wan.health.ObserveRaw(rate)
					}
				}
				// Adaptive FEC: feed the encoder this path's loss estimate
				// so it can code/pass-through accordingly (fec.Params.Adaptive).
				enc.SetLossRate(wan.health.Loss())
				before := wan.health.State()
				wan.health.Tick(now)
				after := wan.health.State()
				if after != before {
					c.log.Info("wan state changed", "wan", wan.id, "state", after.String())
				}
				c.sched.OnState(wan.id, after, wan.health.Loss())
			}
		}
	}
}

// openAndVerify runs the receive pipeline in the security-correct order:
// header check → AEAD authentication → anti-replay. The seq is part of the
// authenticated header, so an unauthenticated attacker cannot slide the
// replay window (window poisoning would be a permanent DoS).
func (c *Client) openAndVerify(sealed []byte) (*frame.Frame, bool) {
	hdr, err := frame.DecodeHeader(sealed)
	if err != nil {
		return nil, false
	}
	if hdr.SessionID != uint64(c.sess.ID) {
		return nil, false // wrong session — per-session key would also fail
	}
	aead, ok := c.getSessionAEAD()
	if !ok {
		return nil, false // PFS session not established yet
	}
	plain, err := crypto.Open(aead, crypto.DirServerToClient, sealed)
	if err != nil {
		return nil, false
	}
	f, err := frame.Decode(plain)
	if err != nil {
		return nil, false
	}
	if !c.sess.CheckReplay(f.Seq) {
		return nil, false
	}
	return f, true
}
