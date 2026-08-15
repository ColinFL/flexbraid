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
}

// Client is the FlexBraid tunnel client (office side).
type Client struct {
	cfg      *config.Config
	log      *slog.Logger
	baseAEAD cipher.AEAD // handshake key (derived from PSK only)
	sessAEAD cipher.AEAD // per-session key (derived from PSK + session ID)
	sess     *session.Client
	wans     []*wanLink
	byWAN    map[string]*wanLink
	sched    *scheduler.Scheduler
	delivery *deliveryBuffer

	probeInterval time.Duration

	// sendErrs throttles repeated send-failure logging (P6).
	sendErrs atomic.Uint64
	// oversizeErrs throttles MTU-exceeded logging (P6).
	oversizeErrs atomic.Uint64
	// noWANErrs throttles 'no usable WAN' logging.
	noWANErrs atomic.Uint64

	ingress *net.UDPConn // read-only after Start
}

// pathMTU is the assumed WAN path MTU for the inner-MTU check. The largest
// frame on the wire is a parity frame: payload + FEC sub-header + frame
// header + AEAD tag, and it must fit the path MTU without IP fragmentation
// (a lost fragment would defeat FEC entirely — design §6.6).
const pathMTU = 1500

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
		return fec.Params{}, fmt.Errorf("fec.mode %q is not implemented until M4 (requires scheduler.affinity: packet)",
			config.FECCrosspath)
	}
	k := fec.DefaultDataShards
	if f.DataShards > 0 {
		k = f.DataShards
	}
	var parity int
	switch f.Mode {
	case config.FECFixed:
		parity = int(math.Ceil(float64(k) * f.FixedOverheadPct / 100.0))
	case config.FECAdaptive:
		l := f.MaxLossPct / 100.0
		if wan != nil && wan.FECMaxLossPct != nil {
			l = *wan.FECMaxLossPct / 100.0
		}
		if l <= 0 || l >= 1 {
			return fec.Params{}, fmt.Errorf("invalid fec max_loss_pct %v (must be 0 < x < 100)", l*100)
		}
		parity = int(math.Ceil(float64(k) * l / (1 - l)))
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
	params := fec.Params{DataShards: k, ParityShards: parity, BlockTimeout: timeout}
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
		if cfg.WANs[i].Transport != config.TransportUDP {
			return nil, fmt.Errorf("M3 supports only udp transport, got %q (faketcp/icmp arrive in M4)", cfg.WANs[i].Transport)
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

	// The session ID is chosen before the session key exists; both sides
	// derive the same per-session key from (PSK, session ID).
	id, err := session.NewID()
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	sessKey := crypto.DeriveSessionKey([]byte(cfg.Crypto.Key), uint64(id))
	sessAEAD, err := crypto.NewAEAD(sessKey, cfg.Crypto.Cipher)
	if err != nil {
		return nil, fmt.Errorf("session cipher: %w", err)
	}

	probeInterval := time.Duration(cfg.Health.ProbeInterval * float64(time.Second))
	if probeInterval <= 0 {
		probeInterval = defaultProbeInterval
	}
	c := &Client{
		cfg:           cfg,
		log:           log,
		baseAEAD:      baseAEAD,
		sessAEAD:      sessAEAD,
		sess:          session.NewClientWithID(id),
		byWAN:         make(map[string]*wanLink),
		sched:         scheduler.New(schedulerOptions(cfg)),
		probeInterval: probeInterval,
	}
	// Per-WAN transports, FEC codecs and health monitors.
	for i := range cfg.WANs {
		wcfg := &cfg.WANs[i]
		params, err := fecParamsFor(cfg, wcfg)
		if err != nil {
			return nil, err
		}
		enc, err := fec.NewEncoder(params)
		if err != nil {
			return nil, fmt.Errorf("wan %s fec encoder: %w", wcfg.ID, err)
		}
		dec, err := fec.NewDecoder(params)
		if err != nil {
			return nil, fmt.Errorf("wan %s fec decoder: %w", wcfg.ID, err)
		}
		mon := health.New(healthOptions(cfg.Health, fecCompensableLoss(params), probeInterval))
		wan := &wanLink{
			id:     wcfg.ID,
			cfg:    *wcfg,
			tr:     transport.NewUDP(wcfg.ID, "", cfg.Server, transport.Bind{Iface: wcfg.Iface, LocalIP: wcfg.LocalIP}),
			enc:    enc,
			dec:    dec,
			health: mon,
		}
		c.wans = append(c.wans, wan)
		c.byWAN[wcfg.ID] = wan
		c.sched.AddPath(wcfg.ID, effectiveCapacity(*wcfg, params, cfg.Scheduler.BalanceBy))
		log.Info("wan configured",
			"wan", wcfg.ID,
			"transport", wcfg.Transport,
			"capacity_mbps", wcfg.CapacityMbps,
			"fec", fecSummary(params))
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

	// One handshake + keepalive + recv loop per WAN.
	var recvWG sync.WaitGroup
	for _, wan := range c.wans {
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
	for _, wan := range c.wans {
		wan.tr.Close() // unblock recvLoops
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

// handshakeLoop sends the FIRST frame immediately and then every
// handshakeInterval, on one WAN. FIRST frames are sealed with the *base*
// key — the server has no session yet, so it cannot know the per-session
// key. The payload carries the WAN's declared capacity so the server can
// weight its own per-path scheduling.
func (c *Client) handshakeLoop(ctx context.Context, wan *wanLink) {
	send := func() {
		payload := make([]byte, 4)
		binary.BigEndian.PutUint32(payload, uint32(wan.cfg.CapacityMbps))
		f := &frame.Frame{
			Flags:     frame.FlagFirst,
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
		payload := make([]byte, 8)
		binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixMilli()))
		f := &frame.Frame{
			Flags:     frame.FlagKeepalive,
			SessionID: uint64(c.sess.ID),
			Seq:       c.sess.NextSeq(),
			Payload:   payload,
		}
		if err := c.send(wan, f, c.sessAEAD); err != nil {
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

// send seals and transmits one frame on a WAN. P4: the WAN's sendMu is held
// for the whole call so a control frame cannot interleave with a data batch.
func (c *Client) send(wan *wanLink, f *frame.Frame, aead cipher.AEAD) error {
	wan.sendMu.Lock()
	defer wan.sendMu.Unlock()
	return c.sendLocked(wan, f, aead)
}

func (c *Client) sendLocked(wan *wanLink, f *frame.Frame, aead cipher.AEAD) error {
	plain, err := f.Encode()
	if err != nil {
		return err
	}
	sealed, err := crypto.Seal(aead, crypto.DirClientToServer, plain)
	if err != nil {
		return err
	}
	return wan.tr.Send(sealed)
}

// sendEncoded seals and transmits one FEC block on its WAN. Data frames
// already carry their seq (assigned before Push, so the parity sub-header
// records the true seqs); parity frames get a fresh seq here. The whole
// block is sent under one hold of the WAN's sendMu (P4).
func (c *Client) sendEncoded(wan *wanLink, frames []*frame.Frame) {
	wan.sendMu.Lock()
	defer wan.sendMu.Unlock()
	for _, f := range frames {
		if f.HasFlag(frame.FlagFECParity) {
			f.Seq = c.sess.NextSeq()
		}
		wan.framesSent.Add(1)
		if err := c.sendLocked(wan, f, c.sessAEAD); err != nil {
			c.noteSendErr(err)
		}
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
			"bytes", n, "mtu", c.cfg.MTU, "count", m)
	}
}

// noteNoWAN logs frames dropped because every WAN is down, throttled.
func (c *Client) noteNoWAN() {
	n := c.noWANErrs.Add(1)
	if n == 1 || n%1000 == 0 {
		c.log.Warn("no usable WAN, dropping inner datagram", "count", n)
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
		// Defense-in-depth: the config validation (fecParamsFor) already
		// bounds the MTU; drop anything that still exceeds it instead of
		// letting an oversized frame hit the WAN.
		if n > c.cfg.MTU {
			c.noteOversize(n)
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		f := &frame.Frame{
			SessionID: uint64(c.sess.ID),
			Seq:       c.sess.NextSeq(), // before Push: sub-header records true seqs
			Payload:   payload,
		}
		wanID, ok := c.sched.Pick(f)
		if !ok {
			c.noteNoWAN()
			continue
		}
		wan := c.byWAN[wanID]
		c.sendEncoded(wan, wan.enc.Push(f))
	}
}

// recvLoop reads one WAN's sealed frames, verifies them, and routes them:
// PONGs feed the health monitor, everything else goes through the WAN's FEC
// decoder into the in-order delivery buffer.
func (c *Client) recvLoop(wan *wanLink) {
	for {
		sealed, _, err := wan.tr.Recv()
		if err != nil {
			return // transport closed
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
		c.deliverToWG(c.delivery.Push(wan.dec.Push(wan.id, f)))
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

// fecTickLoop flushes short FEC blocks on every WAN (both directions) and
// advances the delivery buffer's gap timer.
func (c *Client) fecTickLoop(ctx context.Context) {
	interval := c.wans[0].enc.Params().BlockTimeout / 2
	if interval < time.Millisecond {
		interval = time.Millisecond
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			for _, wan := range c.wans {
				c.sendEncoded(wan, wan.enc.Tick(now))
				c.deliverToWG(c.delivery.Push(wan.dec.Tick(now)))
			}
			c.deliverToWG(c.delivery.Tick(now))
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
				// In-band signal: unrecovered loss on this path, measured
				// from real traffic. Instant under load — no probe latency.
				if lost, received := wan.dec.TakeStreamStats(uint64(c.sess.ID), wan.id); received > 0 {
					rate := float64(lost) / float64(lost+received)
					if rate > 0 {
						wan.health.ObserveInBand(rate)
					}
				}
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
	plain, err := crypto.Open(c.sessAEAD, crypto.DirServerToClient, sealed)
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
