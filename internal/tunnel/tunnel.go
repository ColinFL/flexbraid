// Package tunnel wires the FlexBraid pipeline together for a single WAN
// (M1). It implements the client and server roles that pass inner WireGuard
// traffic through the encrypted frame channel.
//
// Topology (docs/DESIGN.md §3.1, co-located egress):
//
//	[WG client] ──► ingress socket ──► client: seal+send ──► (WAN) ──►
//	    server: recv+open ──► egress socket ──► [WG peer]
//
// Multi-WAN scheduling, FEC and health monitoring land in M2/M3; the
// interfaces here are already shaped for them (Transport per WAN, per-path
// endpoints in session).
//
// Lifecycle: Start() binds all sockets and returns init errors synchronously
// (port busy, bad address); Run(ctx) then starts the goroutines and blocks.
// Socket fields are read-only after Start, so no locking is needed for them.
package tunnel

import (
	"context"
	"crypto/cipher"
	"fmt"
	"log/slog"
	"math"
	"net"
	"time"

	"github.com/ColinFL/flexbraid/internal/config"
	"github.com/ColinFL/flexbraid/internal/crypto"
	"github.com/ColinFL/flexbraid/internal/fec"
	"github.com/ColinFL/flexbraid/internal/frame"
	"github.com/ColinFL/flexbraid/internal/session"
	"github.com/ColinFL/flexbraid/internal/transport"
)

const (
	// handshakeInterval is how often the client (re)sends its FIRST frame.
	// This doubles as a lightweight NAT keepalive and guarantees the server
	// learns the session even if early packets are lost.
	handshakeInterval = 5 * time.Second
	// recvBufSize is the max UDP datagram size we accept.
	recvBufSize = 65535
)

func resolveUDPAddr(s string) (*net.UDPAddr, error) {
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", s, err)
	}
	return addr, nil
}

// Client is the FlexBraid tunnel client (office side).
type Client struct {
	cfg      *config.Config
	log      *slog.Logger
	baseAEAD cipher.AEAD // handshake key (derived from PSK only)
	sessAEAD cipher.AEAD // per-session key (derived from PSK + session ID)
	sess     *session.Client
	wanTr    transport.Transport

	fecEnc *fec.Encoder // client → server
	fecDec *fec.Decoder // server → client

	ingress *net.UDPConn // read-only after Start
}

// fecParamsFromConfig derives codec params from the config. A disabled or
// off-mode FEC yields pass-through codecs (no buffering, no parity).
func fecParamsFromConfig(cfg *config.Config) (fec.Params, error) {
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
	var parity int
	switch f.Mode {
	case config.FECFixed:
		parity = int(math.Ceil(float64(k) * f.FixedOverheadPct / 100.0))
	case config.FECAdaptive:
		l := f.MaxLossPct / 100.0
		parity = int(math.Ceil(float64(k) * l / (1 - l)))
	default:
		return fec.Params{}, fmt.Errorf("unknown fec.mode %q", f.Mode)
	}
	if parity < 1 {
		parity = 1
	}
	return fec.Params{DataShards: k, ParityShards: parity, BlockTimeout: timeout}, nil
}

// NewClient builds a tunnel client from config.
func NewClient(cfg *config.Config, log *slog.Logger) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if len(cfg.WANs) == 0 {
		return nil, fmt.Errorf("client requires at least one WAN")
	}
	if cfg.WANs[0].Transport != config.TransportUDP {
		return nil, fmt.Errorf("M1 supports only udp transport, got %q (faketcp/icmp arrive in M4)", cfg.WANs[0].Transport)
	}
	if len(cfg.WANs) > 1 {
		log.Warn("M1 uses only the first WAN; multi-WAN scheduling arrives in M3",
			"configured", len(cfg.WANs))
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

	wan := cfg.WANs[0]
	c := &Client{
		cfg:      cfg,
		log:      log,
		baseAEAD: baseAEAD,
		sessAEAD: sessAEAD,
		sess:     session.NewClientWithID(id),
		wanTr:    transport.NewUDP(wan.ID, "", cfg.Server),
	}
	params, err := fecParamsFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	c.fecEnc, err = fec.NewEncoder(params)
	if err != nil {
		return nil, fmt.Errorf("fec encoder: %w", err)
	}
	c.fecDec, err = fec.NewDecoder(params)
	if err != nil {
		return nil, fmt.Errorf("fec decoder: %w", err)
	}
	if params.Enabled() {
		log.Info("fec enabled",
			"data_shards", params.DataShards,
			"parity_shards", params.ParityShards,
			"block_timeout_ms", params.BlockTimeout.Milliseconds())
	} else {
		log.Info("fec disabled")
	}
	return c, nil
}

// Start binds the ingress socket and opens the WAN transport. It must be
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

	if err := c.wanTr.Open(); err != nil {
		ingress.Close()
		return err
	}
	return nil
}

// Run starts the client loops and blocks until ctx is cancelled. Call Start
// first.
func (c *Client) Run(ctx context.Context) error {
	defer c.ingress.Close()
	defer c.wanTr.Close()

	c.log.Info("client started",
		"session", fmt.Sprintf("%016x", uint64(c.sess.ID)),
		"ingress", c.cfg.Listen,
		"server", c.cfg.Server,
		"wan", c.wanTr.ID())

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go c.handshakeLoop(ctx)
	go c.fecTickLoop(ctx)

	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		c.recvLoop()
	}()

	err := c.ingressLoop(ctx)
	c.wanTr.Close() // unblocks recvLoop
	<-recvDone
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
// handshakeInterval. FIRST frames are sealed with the *base* key — the
// server has no session yet, so it cannot know the per-session key.
func (c *Client) handshakeLoop(ctx context.Context) {
	send := func() {
		f := &frame.Frame{
			Flags:     frame.FlagFirst,
			SessionID: uint64(c.sess.ID),
			Seq:       c.sess.NextSeq(),
		}
		if err := c.send(f, c.baseAEAD); err != nil {
			c.log.Warn("handshake send failed", "error", err)
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

// send seals and transmits one frame over the WAN transport.
func (c *Client) send(f *frame.Frame, aead cipher.AEAD) error {
	plain, err := f.Encode()
	if err != nil {
		return err
	}
	sealed, err := crypto.Seal(aead, crypto.DirClientToServer, plain)
	if err != nil {
		return err
	}
	return c.wanTr.Send(sealed)
}

// sendEncoded seals and transmits frames produced by the FEC encoder.
// Data frames already carry their seq (assigned before Push, so the parity
// sub-header records the true seqs); parity frames get a fresh seq here.
func (c *Client) sendEncoded(frames []*frame.Frame) {
	for _, f := range frames {
		if f.HasFlag(frame.FlagFECParity) {
			f.Seq = c.sess.NextSeq()
		}
		if err := c.send(f, c.sessAEAD); err != nil {
			c.log.Warn("send failed", "error", err)
		}
	}
}

// ingressLoop relays inner datagrams (WireGuard) into the tunnel.
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
		if c.sess.WGAddr() == nil {
			c.sess.SetWGAddr(addr)
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		f := &frame.Frame{
			SessionID: uint64(c.sess.ID),
			Seq:       c.sess.NextSeq(), // before Push: sub-header records true seqs
			Payload:   payload,
		}
		c.sendEncoded(c.fecEnc.Push(f))
	}
}

// recvLoop relays tunneled replies back to the inner WireGuard peer.
func (c *Client) recvLoop() {
	for {
		sealed, _, err := c.wanTr.Recv()
		if err != nil {
			return // transport closed
		}
		f, ok := c.openAndVerify(sealed)
		if !ok {
			continue
		}
		// Control/keepalive frames carry no inner data; M3 uses them for RTT.
		if f.HasFlag(frame.FlagControl) || f.HasFlag(frame.FlagKeepalive) || len(f.Payload) == 0 {
			continue
		}
		c.deliverToWG(c.fecDec.Push(f))
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

// fecTickLoop flushes short FEC blocks on both directions.
func (c *Client) fecTickLoop(ctx context.Context) {
	interval := c.fecEnc.Params().BlockTimeout / 2
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
			c.sendEncoded(c.fecEnc.Tick(now))
			c.deliverToWG(c.fecDec.Tick(now))
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
