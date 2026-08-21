// Server is the FlexBraid tunnel server (VPS side). It accepts sessions from
// clients over the WAN transport and forwards inner datagrams to the
// WireGuard peer. Each session owns a dedicated egress socket (P1), so WG
// replies return on the socket of the session they belong to.
//
// M3: a session's client may present several paths (WANs, each with its own
// source address). The server tracks per-path health from the client's
// keepalive probes, answers them with PONGs (client-side RTT), and picks a
// path per outbound FEC block through a per-session scheduler (lb/standby).
// The FEC×scheduler invariant (§7.4): blocks are never split across paths.
package tunnel

import (
	"context"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
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
	"github.com/ColinFL/flexbraid/internal/health"
	"github.com/ColinFL/flexbraid/internal/scheduler"
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
	// maxPathsPerSession caps how many WAN addresses one session may use.
	maxPathsPerSession = 16
	// serverHealthTick is the circuit-breaker evaluation interval.
	serverHealthTick = 200 * time.Millisecond
)

// pathState is the server's per-path view of one client session: the
// endpoint address, the client-declared capacity and the health monitor.
// lastArrive/lastKeepalive are atomic (unix nanos): written by the wanLoop
// goroutine, read by the health tick loop.
type pathState struct {
	addr          *net.UDPAddr
	capacity      float64
	health        *health.Monitor
	lastArrive    atomic.Int64 // last frame of ANY kind on this path (liveness)
	lastKeepalive atomic.Int64 // last keepalive arrival (loss measurement)
	// pathSeq is this client-path's monotonic counter for pass-through
	// frames (stamped into BlockSeq under sendMu in sendToSession). The
	// client derives raw per-path loss from gaps in it — the adaptive FEC
	// trigger (Variant A, mirrors wanLink.pathSeq on the client).
	pathSeq uint32
}

// sessState is the server's scheduling state for one client session.
type sessState struct {
	sched    *scheduler.Scheduler
	paths    map[string]*pathState // by path key (addr string)
	lastSeen *net.UDPAddr          // fallback endpoint
}

// Server is the FlexBraid tunnel server (VPS side).
type Server struct {
	cfg       *config.Config
	log       *slog.Logger
	psk       []byte // raw PSK, used to derive per-session keys
	baseAEAD  cipher.AEAD
	mgr       *session.Manager
	wanTr     transport.Transport
	fecParams fec.Params
	fecDec    *fec.Decoder // client → server (all sessions, keyed per path)

	// ann is the JSON-encoded config.ServerAnnounce appended to every
	// KEX_ACK after the ephemeral server X25519 key: the FEC geometry and
	// inner MTU the client must adopt (single source of truth — see
	// config.ServerAnnounce).
	ann []byte

	// egressAddr is the resolved WG peer address (read-only after Start).
	egressAddr *net.UDPAddr

	// sendMu serializes batches of frames on the shared WAN transport so
	// concurrent senders (egress readers, FEC tick, handshake ACK, PONG)
	// cannot interleave frames and reorder them on the wire (P4).
	sendMu sync.Mutex
	// egressWG tracks per-session egress readers for clean shutdown.
	egressWG sync.WaitGroup
	// sendErrs throttles repeated send-failure logging (P6).
	sendErrs atomic.Uint64
	// start marks construction time (telemetry uptime).
	start time.Time

	// states holds per-session scheduling state (guarded by statesMu).
	statesMu sync.Mutex
	states   map[session.ID]*sessState
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
	params, err := fecParamsFor(cfg, nil)
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
	var wanTr transport.Transport
	switch cfg.Transport {
	case config.TransportFakeTCP:
		wanTr = transport.NewFakeTCP("wan", cfg.Listen, "", transport.Bind{})
	case config.TransportICMP:
		wanTr = transport.NewICMP("wan", cfg.Listen, "", transport.Bind{})
	default: // udp (and the empty default)
		wanTr = transport.NewUDP("wan", cfg.Listen, "", transport.Bind{})
	}
	// The announce is baked once at construction: the server's own codecs
	// (fecParams, fecDec, per-session encoders) are built from these very
	// values, so what the server pushes is by construction what it codes
	// with. cfg.Validate() has already defaulted every FEC/MTU field.
	ann, err := json.Marshal(config.ServerAnnounce{Version: config.AnnounceVersion, MTU: cfg.MTU, FEC: cfg.FEC})
	if err != nil {
		return nil, fmt.Errorf("server announce: %w", err)
	}
	return &Server{
		cfg:       cfg,
		log:       log,
		psk:       []byte(cfg.Crypto.Key),
		baseAEAD:  baseAEAD,
		mgr:       session.NewManager(),
		wanTr:     wanTr,
		fecParams: params,
		fecDec:    fecDec,
		ann:       ann,
		states:    make(map[session.ID]*sessState),
		start:     time.Now(),
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
		"wg_peer", s.cfg.WGPeer,
		"scheduler", s.cfg.Scheduler.Mode)

	// Session TTL sweeper.
	sweepDone := make(chan struct{})
	go func() {
		defer close(sweepDone)
		s.sweepLoop(ctx)
	}()

	// FEC block assembly timeouts (short blocks on both directions).
	go s.fecTickLoop(ctx)
	// Circuit breakers for every session's paths.
	go s.healthTickLoop(ctx)

	// wanLoop sits in wanTr.Recv() and only returns when the socket is
	// closed; close it the moment the context dies, or SIGTERM would
	// hang forever (the defer below runs only after wanLoop returns).
	go func() {
		<-ctx.Done()
		s.wanTr.Close()
	}()

	err := s.wanLoop(ctx)
	<-sweepDone
	return err
}

// LocalAddr returns the server's WAN listen address (valid after Start).
func (s *Server) LocalAddr() net.Addr { return s.wanTr.LocalAddr() }

// sweepLoop periodically expires idle sessions and their scheduling state.
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
			if n := s.mgr.ExpireFirsts(sessionTTL); n > 0 {
				s.log.Info("expired handshake replay windows", "count", n)
			}
			s.statesMu.Lock()
			for id := range s.states {
				if s.mgr.Get(id) == nil {
					delete(s.states, id)
				}
			}
			s.statesMu.Unlock()
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

// stateFor returns (creating if needed) the scheduling state for a session.
func (s *Server) stateFor(id session.ID) *sessState {
	s.statesMu.Lock()
	defer s.statesMu.Unlock()
	st := s.states[id]
	if st == nil {
		st = &sessState{
			sched: scheduler.New(scheduler.Options{
				Mode:      string(s.cfg.Scheduler.Mode),
				Affinity:  scheduler.AffPacket, // server schedules whole blocks, never flows
				BalanceBy: string(s.cfg.Scheduler.BalanceBy),
			}),
			paths: make(map[string]*pathState),
		}
		s.states[id] = st
	}
	return st
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
	// key does not exist until the session does). Payload = declared WAN
	// capacity (4 bytes), used to weight the server-side scheduler.
	if hdr.HasFlag(frame.FlagFirst) {
		ua, _ := addr.(*net.UDPAddr)
		if ua == nil {
			return
		}
		// Authenticate before any state change.
		plain, err := crypto.Open(s.baseAEAD, crypto.DirClientToServer, sealed)
		if err != nil {
			return // unauthenticated handshake — drop
		}
		f, err := frame.Decode(plain)
		if err != nil {
			return
		}
		sess := s.mgr.Get(id)
		if sess == nil {
			if s.mgr.Count() >= maxSessions {
				s.log.Warn("session table full, dropping handshake",
					"session", fmt.Sprintf("%016x", uint64(id)))
				return
			}
			// Handshake anti-replay (P8): a replayed captured FIRST must not
			// create a session (each one dials an egress socket and spawns a
			// goroutine — a replay loop would be a memory/socket DoS). The
			// per-ID window is checked before ANY state is created.
			if !s.mgr.CheckFirstReplay(id, hdr.Seq) {
				return // replayed handshake
			}
			// PFS (M5.5): the FIRST payload carries the client's ephemeral
			// X25519 public key after the 4-byte capacity. A pre-PFS client
			// cannot handshake — protocol version moved to the PFS scheme.
			if len(f.Payload) < 4+crypto.PublicKeySize {
				s.log.Warn("dropping pre-PFS handshake", "session", fmt.Sprintf("%016x", uint64(id)))
				return
			}
			clientPub := f.Payload[4 : 4+crypto.PublicKeySize]
			sPriv, sPub, err := crypto.GenerateEphemeralKey()
			if err != nil {
				s.log.Warn("pfs keypair failed, dropping handshake", "error", err)
				return
			}
			shared, err := crypto.ECDHShared(sPriv, clientPub)
			if err != nil {
				s.log.Warn("pfs ecdh failed, dropping handshake", "error", err)
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
			sessKey := crypto.DerivePFSKey(s.psk, shared, uint64(id))
			sessAEAD, err := crypto.NewAEAD(sessKey, s.cfg.Crypto.Cipher)
			if err != nil {
				egress.Close()
				return
			}
			sess = session.NewServerSession(id, sessAEAD)
			sess.ServerPub = sPub
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
		// Register/refresh this path (a WAN of the client).
		s.registerPath(sess, ua, f.Payload)
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
	pathKey := ""
	if ua != nil {
		pathKey = ua.String()
		s.registerPath(sess, ua, nil) // keep the path fresh
	}

	// Keepalive: probe for server-side path health; echo it as a PONG so
	// the client gets an RTT sample. Never goes through FEC.
	if f.HasFlag(frame.FlagKeepalive) {
		if ua != nil {
			s.observeKeepalive(sess, pathKey, ua)
			s.sendPong(sess, ua, f.Payload)
		}
		return
	}
	if len(f.Payload) == 0 {
		return
	}
	// Client → server data: shared decoder keyed by (session, path, block).
	s.forwardDecoded(s.fecDec.Push(pathKey, f))
}

// registerPath creates or refreshes the server-side state for one of the
// client's WANs. payload, when non-nil (FIRST frame), carries the declared
// capacity in the first 4 bytes.
func (s *Server) registerPath(sess *session.ServerSession, ua *net.UDPAddr, payload []byte) {
	pathKey := ua.String()
	st := s.stateFor(sess.ID)

	// st.paths is mutated here (wanLoop goroutine) and ranged over by
	// healthTickLoop — both must hold statesMu. lastSeen is read by
	// pickPath from the egress goroutines, same lock.
	s.statesMu.Lock()
	defer s.statesMu.Unlock()
	st.lastSeen = ua

	ps := st.paths[pathKey]
	if ps == nil {
		if len(st.paths) >= maxPathsPerSession {
			return // path cap reached; keep serving known paths only
		}
		mon := health.New(healthOptions(s.cfg.Health, monitorMaxLoss(s.fecParams), 0))
		ps = &pathState{addr: ua, capacity: 1, health: mon}
		ps.lastArrive.Store(time.Now().UnixNano())
		st.paths[pathKey] = ps
		st.sched.AddPath(pathKey, 1)
		s.log.Info("client path registered",
			"session", fmt.Sprintf("%016x", uint64(sess.ID)),
			"path", pathKey)
	}
	// Any authenticated frame on this path is a liveness signal: the
	// silence watchdog in healthTickLoop uses it, so a busy path cannot
	// be marked DOWN from probe jitter alone.
	ps.lastArrive.Store(time.Now().UnixNano())
	if len(payload) >= 4 {
		capMbps := float64(binary.BigEndian.Uint32(payload[:4]))
		// Trust boundary: the client-declared capacity is untrusted input —
		// a lying client must not be able to grab the server's whole
		// outbound share. Clamp to the server-configured cap (0 = no cap).
		if cap := s.cfg.Scheduler.CapacityCapMbps; cap > 0 && capMbps > cap {
			capMbps = cap
		}
		if capMbps != ps.capacity {
			ps.capacity = capMbps
			st.sched.AddPath(pathKey, s.effectiveCapacityFor(capMbps))
		}
	}
	sess.SetEndpoint(pathKey, ua)
}

// effectiveCapacityFor converts a client-declared capacity into the
// server-side scheduling weight.
func (s *Server) effectiveCapacityFor(capMbps float64) float64 {
	return effectiveCapacity(config.WAN{CapacityMbps: int(capMbps)}, s.fecParams, s.cfg.Scheduler.BalanceBy)
}

// observeKeepalive feeds the path's health monitor from probe arrivals.
//
// A keepalive counts as LOST only when the path is otherwise silent: if
// data frames are flowing, a late keepalive is jitter, not loss — marking
// it missed would false-trip the circuit breaker on a busy path. Total
// silence is handled by the watchdog in healthTickLoop.
func (s *Server) observeKeepalive(sess *session.ServerSession, pathKey string, ua *net.UDPAddr) {
	st := s.stateFor(sess.ID)
	s.statesMu.Lock()
	ps := st.paths[pathKey]
	s.statesMu.Unlock()
	if ps == nil {
		return // not registered (path cap) — ignore
	}
	now := time.Now()
	interval := time.Duration(s.cfg.Health.ProbeInterval) * time.Second
	if interval <= 0 {
		interval = defaultProbeInterval
	}
	// Liveness: the keepalive itself is a genuine response.
	ps.health.NoteAlive()
	lastKA := time.Unix(0, ps.lastKeepalive.Load())
	if lastKA.IsZero() {
		ps.lastKeepalive.Store(now.UnixNano())
		ps.health.ObserveSample(0, 0)
		return
	}
	gap := now.Sub(lastKA)
	ps.lastKeepalive.Store(now.UnixNano())
	lastArr := time.Unix(0, ps.lastArrive.Load())
	if gap > 2*interval && now.Sub(lastArr) > 2*interval {
		// No keepalive AND no data for two intervals: a real loss sample.
		missed := int(gap/interval) - 1
		if missed > 8 {
			missed = 8
		}
		for i := 0; i < missed; i++ {
			ps.health.NoteMissedProbe()
		}
		ps.health.ObserveSample(1, 0)
	} else {
		ps.health.ObserveSample(0, 0)
	}
}

// sendPong echoes a keepalive's timestamp back to the path it came from.
func (s *Server) sendPong(sess *session.ServerSession, ua *net.UDPAddr, ts []byte) {
	f := &frame.Frame{
		Flags:     frame.FlagPong,
		SessionID: uint64(sess.ID),
		Seq:       sess.NextSeq(),
		Payload:   ts,
	}
	s.sendToAddr(sess, ua, f)
}

// sendAck answers a FIRST/KEX_REQ frame with a key-exchange ACK on the
// same path (M5.5): the payload is the session's ephemeral server X25519
// public key, sealed under the base (PSK) key — the client has no session
// key yet, so it can only read the ACK under the base key. The server's
// authoritative FEC/MTU announce is appended after the key; the client
// adopts it (see config.ServerAnnounce).
func (s *Server) sendAck(sess *session.ServerSession, addr *net.UDPAddr) {
	payload := make([]byte, 0, len(sess.ServerPub)+len(s.ann))
	payload = append(payload, sess.ServerPub...)
	payload = append(payload, s.ann...)
	f := &frame.Frame{
		Flags:     frame.FlagControl | frame.FlagKex,
		SessionID: uint64(sess.ID),
		Seq:       sess.NextSeq(),
		Payload:   payload,
	}
	s.sendToAddrKey(sess, addr, f, s.baseAEAD)
}

// sendToAddrKey seals one frame and sends it to one endpoint under sendMu
// (P4), using an explicit key (handshake frames use the base key; data
// frames use the session key via sendToAddr).
func (s *Server) sendToAddrKey(sess *session.ServerSession, addr *net.UDPAddr, f *frame.Frame, aead cipher.AEAD) {
	plain, err := f.Encode()
	if err != nil {
		return
	}
	sealed, err := crypto.Seal(aead, crypto.DirServerToClient, plain)
	if err != nil {
		return
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if err := s.wanTr.SendTo(addr, sealed); err != nil {
		s.noteSendErr(err)
	}
}

// sendToAddr seals one frame and sends it to one endpoint under sendMu (P4).
func (s *Server) sendToAddr(sess *session.ServerSession, addr *net.UDPAddr, f *frame.Frame) {
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
// to that session's client. One goroutine per session; it exits when the
// session's egress socket is closed (expiry or server shutdown). Because
// the socket is per-session, replies are naturally attributed to the right
// client (P1).
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
	s.log.Warn("dropped oversize inner datagram (mtu exceeded)",
		"session", fmt.Sprintf("%016x", uint64(sess.ID)), "bytes", n, "mtu", s.cfg.MTU)
}

// pathForAddr returns the path state for a client endpoint, or nil. It is
// called from sendToSession (under sendMu) to stamp the per-path pass-through
// counter; statesMu serializes the (brief) read.
func (s *Server) pathForAddr(id session.ID, ua *net.UDPAddr) *pathState {
	st := s.stateFor(id)
	s.statesMu.Lock()
	defer s.statesMu.Unlock()
	return st.paths[ua.String()]
}

// pickPath selects the endpoint for one outbound FEC block (M3): the
// per-session scheduler picks among healthy paths; when none are usable it
// falls back to the last heard endpoint so a fully-degraded link keeps
// limping instead of stalling.
func (s *Server) pickPath(sess *session.ServerSession) *net.UDPAddr {
	st := s.stateFor(sess.ID)
	s.statesMu.Lock()
	defer s.statesMu.Unlock()
	if pathKey, ok := st.sched.Pick(nil); ok {
		if ps := st.paths[pathKey]; ps != nil {
			return ps.addr
		}
	}
	return st.lastSeen
}

// sendToSession seals a FEC block with the session's key and delivers the
// whole block to ONE picked endpoint (the FEC×scheduler invariant: a block
// is never split across paths). Data frames already carry their seq; parity
// frames get a fresh seq here. The batch holds sendMu (P4).
func (s *Server) sendToSession(sess *session.ServerSession, frames []*frame.Frame) {
	if len(frames) == 0 {
		return
	}
	// Cross-path FEC: each frame of the block goes over a DIFFERENT path
	// (smooth WRR), so one failed WAN costs only its share of the block.
	// Per-WAN FEC sends the whole block over the best path as before.
	var oneAddr *net.UDPAddr
	cross := s.fecParams.CrossPath
	if !cross {
		oneAddr = s.pickPath(sess)
		if oneAddr == nil {
			return // no path known yet
		}
	}
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	for _, f := range frames {
		if f.HasFlag(frame.FlagFECParity) {
			f.Seq = sess.NextSeq()
		}
		addr := oneAddr
		if cross {
			addr = s.pickCrossPath(sess)
			if addr == nil {
				continue
			}
		}
		// Pass-through frames: stamp this path's monotonic counter into
		// BlockSeq so the client can measure raw per-path loss under load
		// (Variant A). Cross-path always codes, so FlagPassSeq only ever
		// appears in the per-WAN branch.
		if f.HasFlag(frame.FlagPassSeq) && addr != nil {
			if ps := s.pathForAddr(sess.ID, addr); ps != nil {
				f.BlockSeq = ps.pathSeq
				ps.pathSeq++
			}
		}
		plain, err := f.Encode()
		if err != nil {
			continue
		}
		sealed, err := crypto.Seal(sess.AEAD(), crypto.DirServerToClient, plain)
		if err != nil {
			continue
		}
		if err := s.wanTr.SendTo(addr, sealed); err != nil {
			s.noteSendErr(err)
		}
	}
}

// pickCrossPath returns the next path of the session for cross-path FEC:
// smooth WRR per FRAME, so one block's frames spread over all live paths.
func (s *Server) pickCrossPath(sess *session.ServerSession) *net.UDPAddr {
	st := s.stateFor(sess.ID)
	s.statesMu.Lock()
	defer s.statesMu.Unlock()
	pk, ok := st.sched.PickWRR()
	if !ok {
		return nil
	}
	if ps := st.paths[pk]; ps != nil {
		return ps.addr
	}
	return nil
}

// noteSendErr logs send failures at most every 100th occurrence (P6).
func (s *Server) noteSendErr(err error) {
	n := s.sendErrs.Add(1)
	if n == 1 || n%100 == 0 {
		s.log.Warn("reply send failed", "count", n, "error", err)
	}
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

// fecTickLoop flushes short FEC blocks: session encoders (server → client,
// per block picked path) and the shared decoder (client → server).
func (s *Server) fecTickLoop(ctx context.Context) {
	interval := s.fecParams.BlockTimeout / 2
	if interval < 25*time.Millisecond {
		// FEC off / tiny block timeout: the codecs are pass-through and
		// (unlike the client) there is no delivery-buffer gap timer for
		// this loop to drive, so a lazy 250ms tick just keeps the loop
		// alive. The old 1ms clamp idled burned ~4% of a core with FEC
		// disabled (measured on a field VM; same bug as the client's
		// fecTickLoop). FEC mode is structural (reload requires restart),
		// so the cadence never needs to change after start.
		interval = 250 * time.Millisecond
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

// healthTickLoop advances every session's per-path circuit breakers and
// mirrors state changes into the per-session schedulers.
func (s *Server) healthTickLoop(ctx context.Context) {
	t := time.NewTicker(serverHealthTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-t.C:
			interval := time.Duration(s.cfg.Health.ProbeInterval) * time.Second
			if interval <= 0 {
				interval = defaultProbeInterval
			}
			s.statesMu.Lock()
			for id, st := range s.states {
				sess := s.mgr.Get(id)
				if sess == nil {
					continue
				}
				maxPathLoss := 0.0
				for pathKey, ps := range st.paths {
					// Silence watchdog: when NOTHING arrives on a path for
					// several probe intervals — no data, no keepalives — it
					// is dead regardless of what the loss EWMA says. This
					// closes the hole where probe-gap detection only fires
					// on arrival (total silence produced no signal at all).
					if lastArr := time.Unix(0, ps.lastArrive.Load()); !lastArr.IsZero() {
						silence := now.Sub(lastArr)
						if silence > 3*interval {
							missed := int(silence/interval) - 2
							if missed > 4 {
								missed = 4
							}
							for i := 0; i < missed; i++ {
								ps.health.NoteMissedProbe()
							}
							ps.health.ObserveSample(1, 0)
						}
					}
					// In-band signal: unrecovered loss on this client path,
					// from the shared decoder's per-stream counters.
					if lost, received := s.fecDec.TakeStreamStats(uint64(id), pathKey); received > 0 {
						rate := float64(lost) / float64(lost+received)
						if rate > 0 {
							ps.health.ObserveInBand(rate)
						}
					}
					// Raw per-path loss from pass-through frame counters
					// (Variant A): the adaptive trigger under sustained
					// load. Feeds the loss EWMA, no breaker fast-trip.
					if rawLost, rawRecv := s.fecDec.TakePathStats(uint64(id), pathKey); rawRecv > 0 {
						if rate := float64(rawLost) / float64(rawLost+rawRecv); rate > 0 {
							ps.health.ObserveRaw(rate)
						}
					}
					before := ps.health.State()
					ps.health.Tick(now)
					after := ps.health.State()
					if after != before {
						s.log.Info("client path state changed",
							"session", fmt.Sprintf("%016x", uint64(id)),
							"path", pathKey, "state", after.String())
					}
					st.sched.OnState(pathKey, after, ps.health.Loss())
					// Adaptive FEC: drive the session encoder from the
					// WORST path's loss — a block may be scheduled onto any
					// of the session's paths, so redundancy must cover the
					// least reliable one.
					if loss := ps.health.Loss(); loss > maxPathLoss {
						maxPathLoss = loss
					}
				}
				if sess.Enc != nil {
					sess.Enc.SetLossRate(maxPathLoss)
				}
			}
			s.statesMu.Unlock()
		}
	}
}
