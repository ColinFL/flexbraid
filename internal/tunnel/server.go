package tunnel

import (
	"context"
	"crypto/cipher"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ColinFL/flexbraid/internal/config"
	"github.com/ColinFL/flexbraid/internal/crypto"
	"github.com/ColinFL/flexbraid/internal/fec"
	"github.com/ColinFL/flexbraid/internal/frame"
	"github.com/ColinFL/flexbraid/internal/session"
	"github.com/ColinFL/flexbraid/internal/transport"
)

const (
	// sessionTTL drops sessions with no authenticated traffic for this long.
	sessionTTL = 5 * time.Minute
	// sessionSweepInterval is how often the sweeper runs.
	sessionSweepInterval = 30 * time.Second
	// maxSessions caps the session table (anti-DoS bound).
	maxSessions = 1024
)

// Server is the FlexBraid tunnel server (VPS side). It accepts sessions from
// clients over the WAN transport and forwards inner datagrams to the
// WireGuard peer. Each session owns a dedicated egress socket (P1), so WG
// replies return on the socket of the session they belong to — the shared
// single-socket design could not demultiplex multiple clients.
type Server struct {
	cfg       *config.Config
	log       *slog.Logger
	psk       []byte // raw PSK, used to derive per-session keys
	baseAEAD  cipher.AEAD
	mgr       *session.Manager
	wanTr     transport.Transport
	fecParams fec.Params
	fecDec    *fec.Decoder // client → server (all sessions)

	// egressAddr is the resolved WG peer address (read-only after Start).
	egressAddr *net.UDPAddr

	// sendMu serializes batches of frames on the shared WAN transport so
	// concurrent senders (egress readers, FEC tick, handshake ACK) cannot
	// interleave frames and reorder them on the wire (P4).
	sendMu sync.Mutex
	// egressWG tracks per-session egress readers for clean shutdown.
	egressWG sync.WaitGroup
	// sendErrs throttles repeated send-failure logging (P6).
	sendErrs atomic.Uint64
}

// NewServer builds a tunnel server from config.
func NewServer(cfg *config.Config, log *slog.Logger) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if cfg.WGPeer == "" {
		return nil, fmt.Errorf("server requires wg_peer (inner WireGuard peer address)")
	}
	baseKey, err := crypto.DeriveKey([]byte(cfg.Crypto.Key))
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}
	baseAEAD, err := crypto.NewAEAD(baseKey, cfg.Crypto.Cipher)
	if err != nil {
		return nil, fmt.Errorf("cipher: %w", err)
	}
	params, err := fecParamsFromConfig(cfg)
	if err != nil {
		return nil, err
	}
	fecDec, err := fec.NewDecoder(params)
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
	return &Server{
		cfg:       cfg,
		log:       log,
		psk:       []byte(cfg.Crypto.Key),
		baseAEAD:  baseAEAD,
		mgr:       session.NewManager(),
		wanTr:     transport.NewUDP("wan", cfg.Listen, ""),
		fecParams: params,
		fecDec:    fecDec,
	}, nil
}

// Start binds the WAN listen socket and resolves the egress (WG peer)
// address. It must be called before Run and returns init errors
// synchronously. Per-session egress sockets are dialed lazily at session
// creation (see handleClientFrame).
func (s *Server) Start() error {
	if err := s.wanTr.Open(); err != nil {
		return fmt.Errorf("wan listen: %w", err)
	}
	egressAddr, err := resolveUDPAddr(s.cfg.WGPeer)
	if err != nil {
		s.wanTr.Close()
		return fmt.Errorf("wg_peer address: %w", err)
	}
	s.egressAddr = egressAddr
	return nil
}

// Run starts the server loops and blocks until ctx is cancelled. Call Start
// first.
func (s *Server) Run(ctx context.Context) error {
	defer s.wanTr.Close()
	defer func() {
		// Close every session's egress socket first (unblocks the egress
		// readers), then wait for them to exit.
		s.mgr.CloseAll()
		s.egressWG.Wait()
	}()

	s.log.Info("server started",
		"listen", s.cfg.Listen,
		"wg_peer", s.cfg.WGPeer)

	// Session TTL sweeper.
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		s.sweepLoop(ctx)
	}()

	// FEC block assembly timeouts (short blocks on both directions).
	go s.fecTickLoop(ctx)

	err := s.wanLoop(ctx)
	<-sweepDone
	return err
}

// LocalAddr returns the server's WAN listen address (valid after Start).
func (s *Server) LocalAddr() net.Addr { return s.wanTr.LocalAddr() }

// sweepLoop periodically expires idle sessions.
func (s *Server) sweepLoop(ctx context.Context) {
	t := time.NewTicker(sessionSweepInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if n := s.mgr.Expire(sessionTTL); n > 0 {
				s.log.Info("expired idle sessions", "count", n)
			}
		}
	}
}

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
//
// Security order (see docs/DESIGN.md §11): the frame is authenticated before
// anything stateful happens — the replay window, session table and endpoints
// are only touched for frames that passed AEAD. Otherwise an attacker could
// poison the replay window or grow the session table with forged packets.
func (s *Server) handleClientFrame(sealed []byte, addr net.Addr) {
	hdr, err := frame.DecodeHeader(sealed)
	if err != nil {
		return // garbage / wrong version
	}
	id := session.ID(hdr.SessionID)

	// FIRST: handshake — authenticated with the base key (the per-session
	// key does not exist until the session does).
	if hdr.HasFlag(frame.FlagFirst) {
		ua, _ := addr.(*net.UDPAddr)
		if ua == nil {
			return
		}
		// Authenticate before any state change.
		if _, err := crypto.Open(s.baseAEAD, crypto.DirClientToServer, sealed); err != nil {
			return // unauthenticated handshake — drop
		}
		sess := s.mgr.Get(id)
		if sess == nil {
			if s.mgr.Count() >= maxSessions {
				s.log.Warn("session table full, dropping handshake",
					"session", fmt.Sprintf("%016x", uint64(id)))
				return
			}
			// Dial the session's dedicated egress socket to the WG peer.
			// Replies from the WG peer will return on this socket, which is
			// how the server attributes them to the right session (P1).
			egress, err := net.DialUDP("udp", nil, s.egressAddr)
			if err != nil {
				s.log.Warn("egress dial failed, dropping handshake",
					"session", fmt.Sprintf("%016x", uint64(id)), "error", err)
				return
			}
			sessKey := crypto.DeriveSessionKey(s.psk, uint64(id))
			sessAEAD, err := crypto.NewAEAD(sessKey, s.cfg.Crypto.Cipher)
			if err != nil {
				egress.Close()
				return
			}
			sess = session.NewServerSession(id, sessAEAD)
			// Per-session FEC encoder: blocks must never mix sessions,
			// because parity frames are sealed with the session's key.
			enc, err := fec.NewEncoder(s.fecParams)
			if err != nil {
				egress.Close()
				return
			}
			sess.Enc = enc
			sess.SetEgress(egress)
			s.mgr.Put(sess)
			s.egressWG.Add(1)
			go s.egressReader(sess)
		}
		if !sess.CheckReplay(hdr.Seq) {
			return // replayed handshake
		}
		sess.Touch()
		sess.SetEndpoint(s.wanTr.ID(), ua)
		s.sendAck(sess, ua)
		return
	}

	// Data frame: session must exist and be authenticated with its key.
	sess := s.mgr.Get(id)
	if sess == nil {
		return // unknown session, drop
	}
	plain, err := crypto.Open(sess.AEAD(), crypto.DirClientToServer, sealed)
	if err != nil {
		return // auth failure / tampering
	}
	if !sess.CheckReplay(hdr.Seq) {
		return
	}
	f, err := frame.Decode(plain)
	if err != nil {
		return
	}
	sess.Touch()
	ua, _ := addr.(*net.UDPAddr)
	if ua != nil {
		sess.SetEndpoint(s.wanTr.ID(), ua) // keep the path fresh
	}
	if len(f.Payload) == 0 {
		return
	}
	s.forwardDecoded(s.fecDec.Push(f))
}

// forwardDecoded writes decoded inner datagrams to the egress socket of the
// session each frame belongs to (P1): the WG peer's replies return on the
// same socket, which is what routes them back to the right session. Used
// both for direct delivery (handleClientFrame) and for frames assembled by
// the shared decoder (fecTickLoop), where sessions can be mixed.
func (s *Server) forwardDecoded(frames []*frame.Frame) {
	for _, f := range frames {
		sess := s.mgr.Get(session.ID(f.SessionID))
		if sess == nil {
			continue // session expired between decode and delivery
		}
		if _, err := sess.Egress().Write(f.Payload); err != nil {
			s.log.Warn("egress write failed", "error", err)
		}
	}
}

// sendAck answers a FIRST frame with a CONTROL ACK on the same path, sealed
// with the session key. Holds sendMu so the ACK cannot interleave with
// data batches on the WAN (P4).
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
	sealed, err := crypto.Seal(sess.AEAD(), crypto.DirServerToClient, plain)
	if err != nil {
		return
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if err := s.wanTr.SendTo(addr, sealed); err != nil {
		s.noteSendErr(err)
	}
}

// egressReader relays inner replies (from the WG peer) of one session back
// to that session's client endpoints. One goroutine per session; it exits
// when the session's egress socket is closed (expiry or server shutdown).
// Because the socket is per-session, replies are naturally attributed to
// the right client (P1).
func (s *Server) egressReader(sess *session.ServerSession) {
	defer s.egressWG.Done()
	buf := make([]byte, recvBufSize)
	for {
		n, _, err := sess.Egress().ReadFromUDP(buf)
		if err != nil {
			return // egress closed
		}
		if n > s.cfg.MTU {
			s.noteOversize(sess, n)
			continue
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		f := &frame.Frame{
			SessionID: uint64(sess.ID),
			Seq:       sess.NextSeq(), // before Push: sub-header records true seqs
			Payload:   payload,
		}
		if sess.Enc != nil {
			s.sendToSession(sess, sess.Enc.Push(f))
		} else {
			s.sendToSession(sess, []*frame.Frame{f})
		}
	}
}

// noteOversize logs dropped inner datagrams that exceed the configured MTU.
func (s *Server) noteOversize(sess *session.ServerSession, n int) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	s.log.Warn("dropped oversize inner datagram (mtu exceeded)",
		"session", fmt.Sprintf("%016x", uint64(sess.ID)), "bytes", n, "mtu", s.cfg.MTU)
}

// sendToSession seals frames with the session's key and delivers them to
// every endpoint of the session. Data frames already carry their seq;
// parity frames get a fresh seq here. The batch holds sendMu so concurrent
// senders cannot interleave frames on the WAN (P4).
func (s *Server) sendToSession(sess *session.ServerSession, frames []*frame.Frame) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	for _, f := range frames {
		if f.HasFlag(frame.FlagFECParity) {
			f.Seq = sess.NextSeq()
		}
		plain, err := f.Encode()
		if err != nil {
			continue
		}
		sealed, err := crypto.Seal(sess.AEAD(), crypto.DirServerToClient, plain)
		if err != nil {
			continue
		}
		for _, ep := range sess.Endpoints() {
			if err := s.wanTr.SendTo(ep, sealed); err != nil {
				s.noteSendErr(err)
			}
		}
	}
}

// noteSendErr logs send failures at most every 100th occurrence (P6).
func (s *Server) noteSendErr(err error) {
	n := s.sendErrs.Add(1)
	if n == 1 || n%100 == 0 {
		s.log.Warn("reply send failed", "count", n, "error", err)
	}
}

// fecTickLoop flushes short FEC blocks: session encoders (server → client)
// and the shared decoder (client → server).
func (s *Server) fecTickLoop(ctx context.Context) {
	interval := s.fecParams.BlockTimeout / 2
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
			for _, sess := range s.mgr.All() {
				if sess.Enc != nil {
					s.sendToSession(sess, sess.Enc.Tick(now))
				}
			}
			s.forwardDecoded(s.fecDec.Tick(now))
		}
	}
}
