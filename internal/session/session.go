// Package session manages FlexBraid tunnel sessions.
//
// The core idea (see docs/DESIGN.md §9): a session is keyed by a random
// 64-bit ID chosen by the client, NOT by the client's source IP. This is what
// makes WAN failover seamless — when the client switches uplinks (and its NAT
// mapping changes), the server keeps the session because the ID is stable.
// Each WAN is tracked as a separate endpoint so active load balancing can
// answer every uplink on the path it arrived on.
//
// Concurrency: seq counters are atomic (the handshake/egress loops and the
// data loops call NextSeq from different goroutines); the per-path endpoint
// map is mutex-protected; every other field is read-only after creation.
package session

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ColinFL/flexbraid/internal/crypto"
	"github.com/ColinFL/flexbraid/internal/frame"
)

// ID is a 64-bit tunnel session identifier chosen by the client.
type ID uint64

// NewID returns a fresh random session ID.
func NewID() (ID, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return ID(binary.BigEndian.Uint64(b[:])), nil
}

// Client is the client-side session state.
type Client struct {
	ID     ID
	seq    atomic.Uint32       // next outgoing seq (client → server)
	replay crypto.ReplayWindow // server → client frames

	mu     sync.Mutex
	wgAddr *net.UDPAddr // the inner WireGuard peer's address (ingress side)
}

// NewClient creates client-side session state with a fresh ID.
func NewClient() (*Client, error) {
	id, err := NewID()
	if err != nil {
		return nil, err
	}
	return NewClientWithID(id), nil
}

// NewClientWithID builds client-side session state for a caller-chosen ID.
// The tunnel layer uses this to derive the per-session key before the
// session exists.
func NewClientWithID(id ID) *Client {
	return &Client{ID: id, replay: *crypto.NewReplayWindow(crypto.DefaultReplayWindow)}
}

// NextSeq returns the next outgoing sequence number.
func (c *Client) NextSeq() uint32 { return c.seq.Add(1) }

// CheckReplay validates a server→client frame's seq against the replay
// window (returns false for replayed/too-old frames).
func (c *Client) CheckReplay(seq uint32) bool { return c.replay.CheckAndMark(seq) }

// SetWGAddr records the inner peer address (the WireGuard client talking to
// the ingress socket). M1 assumes a single inner peer.
func (c *Client) SetWGAddr(addr *net.UDPAddr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wgAddr = addr
}

// WGAddr returns the recorded inner peer address, if any.
func (c *Client) WGAddr() *net.UDPAddr {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wgAddr
}

// FrameCodec is the per-session FEC encoder contract the tunnel injects
// into server sessions. It is satisfied by *fec.Encoder.
type FrameCodec interface {
	Push(*frame.Frame) []*frame.Frame
	Tick(time.Time) []*frame.Frame
	// SetLossRate feeds the session's worst-path loss estimate (0..1) so
	// an adaptive encoder can code/pass-through accordingly.
	SetLossRate(float64)
}

// ServerSession is the server-side state for one tunnel.
type ServerSession struct {
	ID     ID
	aead   cipher.AEAD // per-session key (derived from PSK + session ID)
	Enc    FrameCodec  // per-session FEC encoder (server → client), may be nil
	seq    atomic.Uint32
	replay crypto.ReplayWindow // client → server frames

	// egress is the session's dedicated UDP socket to the WG peer (P1:
	// per-session egress). Replies from the WG peer return on this socket,
	// so they are naturally attributed to the right session — the old
	// shared socket could not demultiplex multiple clients. Set once at
	// session creation before the egress reader goroutine starts, then
	// read-only; closed by the sweeper or server shutdown.
	egress *net.UDPConn

	mu        sync.Mutex
	endpoints map[string]*net.UDPAddr // per-path endpoint (WAN ID → address)

	lastSeen atomic.Int64 // unix nanos of the last valid frame
}

// NewServerSession creates server-side state for a session. aead is the
// per-session AEAD derived from the PSK and the session ID.
func NewServerSession(id ID, aead cipher.AEAD) *ServerSession {
	s := &ServerSession{
		ID:        id,
		aead:      aead,
		replay:    *crypto.NewReplayWindow(crypto.DefaultReplayWindow),
		endpoints: make(map[string]*net.UDPAddr),
	}
	s.Touch()
	return s
}

// NextSeq returns the next outgoing sequence number.
func (s *ServerSession) NextSeq() uint32 { return s.seq.Add(1) }

// CheckReplay validates a client→server frame's seq.
func (s *ServerSession) CheckReplay(seq uint32) bool { return s.replay.CheckAndMark(seq) }

// Touch records activity (called on every authenticated frame).
func (s *ServerSession) Touch() { s.lastSeen.Store(time.Now().UnixNano()) }

// IdleSince returns the time of the last authenticated frame.
func (s *ServerSession) IdleSince() time.Time {
	return time.Unix(0, s.lastSeen.Load())
}

// AEAD returns the per-session cipher (read-only after construction).
func (s *ServerSession) AEAD() cipher.AEAD { return s.aead }

// SetEgress attaches the session's dedicated egress socket to the WG peer.
// Must be called once, before the egress reader goroutine starts.
func (s *ServerSession) SetEgress(c *net.UDPConn) { s.egress = c }

// Egress returns the session's egress socket (nil until SetEgress).
func (s *ServerSession) Egress() *net.UDPConn { return s.egress }

// CloseEgress closes the session's egress socket, unblocking its reader.
// Safe to call multiple times.
func (s *ServerSession) CloseEgress() {
	if s.egress != nil {
		s.egress.Close()
	}
}

// SetEndpoint records (or updates) the return address for a path (WAN).
func (s *ServerSession) SetEndpoint(pathID string, addr *net.UDPAddr) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.endpoints[pathID] = addr
}

// Endpoints returns a snapshot of the per-path endpoints.
func (s *ServerSession) Endpoints() map[string]*net.UDPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]*net.UDPAddr, len(s.endpoints))
	for k, v := range s.endpoints {
		out[k] = v
	}
	return out
}

// Manager holds all active server-side sessions.
type Manager struct {
	mu       sync.Mutex
	sessions map[ID]*ServerSession
	// firstWindows holds handshake anti-replay state for sessions that do
	// not exist yet (P8): a replayed captured FIRST frame must not be able
	// to create a session — each creation dials an egress socket and
	// spawns a goroutine, so an unbounded replay loop would be a socket
	// and memory DoS. Entries expire via ExpireFirsts.
	firstWindows map[ID]*firstWindow
}

// firstWindow is the anti-replay window for one not-yet-existing session.
type firstWindow struct {
	win     *crypto.ReplayWindow
	created time.Time
}

// maxFirstWindows bounds the handshake replay table (anti-DoS).
const maxFirstWindows = 4096

// NewManager creates an empty session manager.
func NewManager() *Manager {
	return &Manager{
		sessions:     make(map[ID]*ServerSession),
		firstWindows: make(map[ID]*firstWindow),
	}
}

// CheckFirstReplay validates a FIRST-frame seq for a session that does not
// exist yet, creating the per-ID window on first sight. Returns false for a
// replayed or too-old seq. Only meaningful before a session exists; once
// the session is up its own window takes over.
func (m *Manager) CheckFirstReplay(id ID, seq uint32) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	fw := m.firstWindows[id]
	if fw == nil {
		if len(m.firstWindows) >= maxFirstWindows {
			// Table full: evict the oldest entry to stay bounded.
			var oldest ID
			var oldestT time.Time
			for k, v := range m.firstWindows {
				if oldestT.IsZero() || v.created.Before(oldestT) {
					oldest, oldestT = k, v.created
				}
			}
			delete(m.firstWindows, oldest)
		}
		fw = &firstWindow{win: crypto.NewReplayWindow(crypto.DefaultReplayWindow), created: time.Now()}
		m.firstWindows[id] = fw
	}
	return fw.win.CheckAndMark(seq)
}

// ExpireFirsts drops handshake replay windows older than ttl.
func (m *Manager) ExpireFirsts(ttl time.Duration) int {
	cutoff := time.Now().Add(-ttl)
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for id, fw := range m.firstWindows {
		if fw.created.Before(cutoff) {
			delete(m.firstWindows, id)
			n++
		}
	}
	return n
}

// Get returns the session with the given ID, or nil.
func (m *Manager) Get(id ID) *ServerSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id]
}

// Put stores a session (call only after the FIRST frame passed
// authentication — never create entries for unauthenticated traffic).
func (m *Manager) Put(s *ServerSession) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.ID] = s
}

// Delete removes the session with the given ID.
func (m *Manager) Delete(id ID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, id)
}

// Count returns the number of active sessions.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// All returns a snapshot of all sessions (used by the egress loop to fan
// out inner replies to every connected client).
func (m *Manager) All() []*ServerSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*ServerSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}

// Expire removes sessions whose last authenticated frame is older than ttl
// and closes their egress sockets (which also stops their egress readers).
// Returns the number of sessions removed.
func (m *Manager) Expire(ttl time.Duration) int {
	cutoff := time.Now().Add(-ttl)
	var victims []*ServerSession
	m.mu.Lock()
	for id, s := range m.sessions {
		if s.IdleSince().Before(cutoff) {
			victims = append(victims, s)
			delete(m.sessions, id)
		}
	}
	m.mu.Unlock()
	for _, s := range victims {
		s.CloseEgress()
	}
	return len(victims)
}

// CloseAll closes every session's egress socket and clears the table.
// Used at server shutdown to unblock all egress readers.
func (m *Manager) CloseAll() {
	m.mu.Lock()
	sessions := make([]*ServerSession, 0, len(m.sessions))
	for id, s := range m.sessions {
		sessions = append(sessions, s)
		delete(m.sessions, id)
	}
	m.mu.Unlock()
	for _, s := range sessions {
		s.CloseEgress()
	}
}
