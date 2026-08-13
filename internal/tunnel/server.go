package tunnel

import (
	"context"
	"crypto/cipher"
	"fmt"
	"log/slog"
	"net"

	"github.com/ColinFL/flexbraid/internal/config"
	"github.com/ColinFL/flexbraid/internal/crypto"
	"github.com/ColinFL/flexbraid/internal/frame"
	"github.com/ColinFL/flexbraid/internal/session"
	"github.com/ColinFL/flexbraid/internal/transport"
)

// Server is the FlexBraid tunnel server (VPS side). It accepts sessions from
// clients over the WAN transport and forwards inner datagrams to the
// WireGuard peer over a connected egress socket.
type Server struct {
	cfg    *config.Config
	log    *slog.Logger
	aead   cipher.AEAD
	mgr    *session.Manager
	wanTr  transport.Transport
	egress *net.UDPConn
}

// NewServer builds a tunnel server from config.
func NewServer(cfg *config.Config, log *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.WGPeer == "" {
		return nil, fmt.Errorf("server requires wg_peer (inner WireGuard peer address)")
	}
	key, err := crypto.DeriveKey([]byte(cfg.Crypto.Key))
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	aead, err := crypto.NewAEAD(key, cfg.Crypto.Cipher)
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}
	return &Server{
		cfg:   cfg,
		log:   log,
		aead:  aead,
		mgr:   session.NewManager(),
		wanTr: transport.NewUDP("wan", cfg.Listen, ""),
	}, nil
}

// Run starts the server and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	if err := s.wanTr.Open(); err != nil {
		return fmt.Errorf("wan listen: %w", err)
	}
	defer s.wanTr.Close()

	egress, err := net.DialUDP("udp", nil, mustUDPAddr(s.cfg.WGPeer))
	if err != nil {
		return fmt.Errorf("egress dial %s: %w", s.cfg.WGPeer, err)
	}
	s.egress = egress
	defer egress.Close()

	s.log.Info("server started",
		"listen", s.cfg.Listen,
		"wg_peer", s.cfg.WGPeer)

	// Inner replies (WG → client) arrive on the egress socket; fan them out
	// to every known session endpoint.
	egressDone := make(chan struct{})
	go func() {
		defer close(egressDone)
		s.egressLoop()
	}()

	err = s.wanLoop(ctx)
	s.wanTr.Close() // unblocks nothing on egress, but keeps cleanup tidy
	s.egress.Close()
	<-egressDone
	return err
}

// LocalAddr returns the server's WAN listen address (nil before Run).
func (s *Server) LocalAddr() net.Addr { return s.wanTr.LocalAddr() }

// wanLoop receives client frames on the WAN transport.
func (s *Server) wanLoop(ctx context.Context) error {
	for {
		sealed, addr, err := s.wanTr.Recv()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("wan recv: %w", err)
		}
		s.handleClientFrame(sealed, addr)
	}
}

// handleClientFrame processes one frame from a client endpoint.
func (s *Server) handleClientFrame(sealed []byte, addr net.Addr) {
	hdr, err := frame.DecodeHeader(sealed)
	if err != nil {
		return // garbage / wrong version
	}
	id := session.ID(hdr.SessionID)

	// FIRST: (re)establish the session and answer with an ACK.
	if hdr.HasFlag(frame.FlagFirst) {
		sess := s.mgr.GetOrCreate(id)
		if !sess.CheckReplay(hdr.Seq) {
			return
		}
		if _, err := crypto.Open(s.aead, crypto.DirClientToServer, sealed); err != nil {
			s.log.Warn("handshake failed auth", "session", fmt.Sprintf("%016x", uint64(id)))
			return
		}
		ua, _ := addr.(*net.UDPAddr)
		sess.SetEndpoint(s.wanTr.ID(), ua)
		s.sendAck(sess, ua)
		return
	}

	sess := s.mgr.Get(id)
	if sess == nil {
		return // unknown session, drop
	}
	if !sess.CheckReplay(hdr.Seq) {
		return
	}
	plain, err := crypto.Open(s.aead, crypto.DirClientToServer, sealed)
	if err != nil {
		return // auth failure / tampering
	}
	f, err := frame.Decode(plain)
	if err != nil {
		return
	}
	ua, _ := addr.(*net.UDPAddr)
	if ua != nil {
		sess.SetEndpoint(s.wanTr.ID(), ua) // keep the path fresh
	}
	if len(f.Payload) == 0 {
		return
	}
	if _, err := s.egress.Write(f.Payload); err != nil {
		s.log.Warn("egress write failed", "error", err)
	}
}

// sendAck answers a FIRST frame with a CONTROL ACK on the same path.
func (s *Server) sendAck(sess *session.ServerSession, addr *net.UDPAddr) {
	f := &frame.Frame{
		Flags:     frame.FlagControl,
		SessionID: uint64(sess.ID),
		Seq:       sess.NextSeq(),
	}
	plain, err := f.Encode()
	if err != nil {
		return
	}
	sealed, err := crypto.Seal(s.aead, crypto.DirServerToClient, plain)
	if err != nil {
		return
	}
	if err := s.wanTr.SendTo(addr, sealed); err != nil {
		s.log.Warn("ack send failed", "error", err)
	}
}

// egressLoop relays inner replies (from the WG peer) back to every client
// session endpoint.
func (s *Server) egressLoop() {
	buf := make([]byte, recvBufSize)
	for {
		n, _, err := s.egress.ReadFromUDP(buf)
		if err != nil {
			return // egress closed
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		for _, sess := range s.mgr.All() {
			for pathID, ep := range sess.Endpoints() {
				f := &frame.Frame{
					SessionID: uint64(sess.ID),
					Seq:       sess.NextSeq(),
					Payload:   payload,
				}
				plain, err := f.Encode()
				if err != nil {
					continue
				}
				sealed, err := crypto.Seal(s.aead, crypto.DirServerToClient, plain)
				if err != nil {
					continue
				}
				if err := s.wanTr.SendTo(ep, sealed); err != nil {
					s.log.Warn("reply send failed", "path", pathID, "error", err)
				}
			}
		}
	}
}
