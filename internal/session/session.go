// Package session manages FlexBraid tunnel sessions.
//
// The core idea (see docs/DESIGN.md §9): a session is keyed by a random
// 64-bit ID chosen by the client, NOT by the client's source IP. This is what
// makes WAN failover seamless — when the client switches uplinks (and its NAT
// mapping changes), the server keeps the session because the ID is stable.
// Each WAN is tracked as a separate endpoint so active load balancing can
// answer every uplink on the path it arrived on.
package session

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"

	"github.com/ColinFL/flexbraid/internal/crypto"
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
	seq    uint32              // next outgoing seq (client → server)
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
	return &Client{ID: id, replay: *crypto.NewReplayWindow(crypto.DefaultReplayWindow)}, nil
}

// NextSeq returns the next outgoing sequence number.
func (c *Client) NextSeq() uint32 {
	c.seq++
	return c.seq
}

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

// ServerSession is the server-side state for one tunnel.
type ServerSession struct {
	ID     ID
	seq    uint32              // next outgoing seq (server → client)
	replay crypto.ReplayWindow // client → server frames

	mu        sync.Mutex
	endpoints map[string]*net.UDPAddr // per-path endpoint (WAN ID → address)
}

// NewServerSession creates server-side state for a session.
func NewServerSession(id ID) *ServerSession {
	return &ServerSession{
		ID:        id,
		replay:    *crypto.NewReplayWindow(crypto.DefaultReplayWindow),
		endpoints: make(map[string]*net.UDPAddr),
	}
}

// NextSeq returns the next outgoing sequence number.
func (s *ServerSession) NextSeq() uint32 {
	s.seq++
	return s.seq
}

// CheckReplay validates a client→server frame's seq.
func (s *ServerSession) CheckReplay(seq uint32) bool { return s.replay.CheckAndMark(seq) }

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
}

// NewManager creates an empty session manager.
func NewManager() *Manager {
	return &Manager{sessions: make(map[ID]*ServerSession)}
}

// Get returns the session with the given ID, or nil.
func (m *Manager) Get(id ID) *ServerSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.sessions[id]
}

// GetOrCreate returns the session, creating it if absent.
func (m *Manager) GetOrCreate(id ID) *ServerSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		s = NewServerSession(id)
		m.sessions[id] = s
	}
	return s
}

// All returns a snapshot of all sessions (used by the egress loop to
// fan out inner replies to every connected client).
func (m *Manager) All() []*ServerSession {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*ServerSession, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}
