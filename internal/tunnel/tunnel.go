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
package tunnel

import (
	"context"
	"crypto/cipher"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/ColinFL/flexbraid/internal/config"
	"github.com/ColinFL/flexbraid/internal/crypto"
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

func mustUDPAddr(s string) *net.UDPAddr {
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		panic(fmt.Sprintf("resolve %q: %v", s, err))
	}
	return addr
}

// channel carries the AEAD plus the direction context for one side.
type channel struct {
	aead cipher.AEAD
	dir  crypto.NonceDirection
}

// Client is the FlexBraid tunnel client (office side).
type Client struct {
	cfg     *config.Config
	log     *slog.Logger
	ch      channel
	sess    *session.Client
	wanTr   transport.Transport
	ingress *net.UDPConn
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
	ch, err := newChannel(cfg)
	if err != nil {
		return nil, err
	}
	sess, err := session.NewClient()
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	wan := cfg.WANs[0]
	return &Client{
		cfg:   cfg,
		log:   log,
		ch:    ch,
		sess:  sess,
		wanTr: transport.NewUDP(wan.ID, "", cfg.Server),
	}, nil
}

// Run starts the client and blocks until ctx is cancelled.
func (c *Client) Run(ctx context.Context) error {
	var err error
	c.ingress, err = net.ListenUDP("udp", mustUDPAddr(c.cfg.Listen))
	if err != nil {
		return fmt.Errorf("ingress listen %s: %w", c.cfg.Listen, err)
	}
	defer c.ingress.Close()

	if err := c.wanTr.Open(); err != nil {
		return err
	}
	defer c.wanTr.Close()

	c.log.Info("client started",
		"session", fmt.Sprintf("%016x", uint64(c.sess.ID)),
		"ingress", c.cfg.Listen,
		"server", c.cfg.Server,
		"wan", c.wanTr.ID())

	// Periodic FIRST handshake (also keeps the NAT mapping warm).
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go c.handshakeLoop(ctx)

	recvDone := make(chan struct{})
	go func() {
		defer close(recvDone)
		c.recvLoop()
	}()

	err = c.ingressLoop(ctx)
	c.wanTr.Close() // unblocks recvLoop
	<-recvDone
	return err
}

// LocalAddr returns the client's ingress address (nil before Run).
func (c *Client) LocalAddr() *net.UDPAddr {
	if c.ingress == nil {
		return nil
	}
	return c.ingress.LocalAddr().(*net.UDPAddr)
}

// handshakeLoop sends the FIRST frame immediately and then every
// handshakeInterval.
func (c *Client) handshakeLoop(ctx context.Context) {
	send := func() {
		f := &frame.Frame{
			Flags:     frame.FlagFirst,
			SessionID: uint64(c.sess.ID),
			Seq:       c.sess.NextSeq(),
		}
		if err := c.send(f); err != nil {
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
func (c *Client) send(f *frame.Frame) error {
	plain, err := f.Encode()
	if err != nil {
		return err
	}
	sealed, err := crypto.Seal(c.ch.aead, c.ch.dir, plain)
	if err != nil {
		return err
	}
	return c.wanTr.Send(sealed)
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
			Seq:       c.sess.NextSeq(),
			Payload:   payload,
		}
		if err := c.send(f); err != nil {
			c.log.Warn("send failed", "error", err)
		}
	}
}

// recvLoop relays tunneled replies back to the inner WireGuard peer.
func (c *Client) recvLoop() {
	for {
		sealed, _, err := c.wanTr.Recv()
		if err != nil {
			return // transport closed
		}
		plain, ok := c.openAndVerify(sealed, crypto.DirServerToClient)
		if !ok {
			continue
		}
		f, err := frame.Decode(plain)
		if err != nil {
			continue
		}
		// Control/keepalive frames carry no inner data; M3 uses them for RTT.
		if f.HasFlag(frame.FlagControl) || f.HasFlag(frame.FlagKeepalive) || len(f.Payload) == 0 {
			continue
		}
		addr := c.sess.WGAddr()
		if addr == nil {
			continue // no inner peer yet
		}
		if _, err := c.ingress.WriteToUDP(f.Payload, addr); err != nil {
			c.log.Warn("egress to inner peer failed", "error", err)
		}
	}
}

// openAndVerify runs the receive pipeline: header check → anti-replay → AEAD.
func (c *Client) openAndVerify(sealed []byte, dir crypto.NonceDirection) ([]byte, bool) {
	hdr, err := frame.DecodeHeader(sealed)
	if err != nil {
		return nil, false
	}
	if !c.sess.CheckReplay(hdr.Seq) {
		return nil, false
	}
	plain, err := crypto.Open(c.ch.aead, dir, sealed)
	if err != nil {
		return nil, false
	}
	return plain, true
}

func newChannel(cfg *config.Config) (channel, error) {
	key, err := crypto.DeriveKey([]byte(cfg.Crypto.Key))
	if err != nil {
		return channel{}, fmt.Errorf("derive key: %w", err)
	}
	aead, err := crypto.NewAEAD(key, cfg.Crypto.Cipher)
	if err != nil {
		return channel{}, fmt.Errorf("cipher: %w", err)
	}
	return channel{aead: aead, dir: crypto.DirClientToServer}, nil
}
