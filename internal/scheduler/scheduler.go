// Package scheduler picks a WAN per inner datagram (client side) or per FEC
// block (server side), honouring the health monitor's circuit-breaker states
// (docs/DESIGN.md §7).
//
// Modes:
//   - lb — active load balancing across all usable WANs, weighted by
//     declared capacity (and optionally FEC overhead); DEGRADED paths carry
//     a reduced weight, DOWN paths are excluded entirely (graceful drain).
//   - standby — one active WAN (highest priority = config order), the rest
//     warm; the active path is switched on failure.
//
// Affinity:
//   - packet — pick per frame (the mode that actually load-balances a
//     single WireGuard flow inside the tunnel).
//   - flow — consistent-hash the inner 4-tuple so a connection sticks to
//     one WAN while healthy (useful for many independent inner flows, e.g.
//     OpenVPN; with WireGuard inside, everything hashes to one WAN by
//     design).
//
// The FEC×scheduler coupling invariant (§7.4): the server hands *complete
// blocks* to the scheduler, never individual frames of a block, so per-WAN
// FEC stays coherent. Cross-path FEC (§6.4) is the explicit exception —
// PickWRR spreads one block's frames over every live path.
package scheduler

import (
	"encoding/binary"
	"math/rand"
	"sort"
	"sync"

	"github.com/ColinFL/flexbraid/internal/frame"
	"github.com/ColinFL/flexbraid/internal/health"
)

// Options configures a Scheduler (values mirror the config surface).
type Options struct {
	Mode      string // "lb" | "standby"
	Affinity  string // "packet" | "flow"
	BalanceBy string // "capacity" | "fec" | "roundrobin"
}

// Defaults matching the config package.
const (
	ModeLB      = "lb"
	ModeStandby = "standby"
	AffPacket   = "packet"
	AffFlow     = "flow"
	ByCapacity  = "capacity"
	ByFEC       = "fec"
	ByRound     = "roundrobin"
)

// weightFactor scales a path's weight by its circuit-breaker state:
// healthy carries full weight, degraded carries a token amount (drain —
// new work mostly stops, in-flight blocks finish), down carries none.
const (
	weightHealthy  = 1.0
	weightDegraded = 0.2
)

type path struct {
	id       string
	capacity float64 // effective capacity (mbps, FEC-overhead-adjusted)
	state    health.State
	loss     float64
	rr       float64 // smooth-WRR accumulator (cross-path FEC, packet affinity)
}

// Scheduler is concurrency-safe.
type Scheduler struct {
	opts  Options
	mu    sync.Mutex
	paths []*path // insertion order (standby priority)
	byID  map[string]*path

	// Consistent-hash ring (flow affinity): sorted node hashes + node→path.
	ring        []uint32
	ringPaths   map[uint32]string
	lastRingVer uint64 // ring is valid while ringVer == lastRingVer
	ringVer     uint64 // bumped whenever the usable set may have changed

	rng *rand.Rand
}

// PathInfo is a read-only snapshot of one path for telemetry.
type PathInfo struct {
	ID           string  `json:"id"`
	CapacityMbps float64 `json:"capacity_mbps"`
	State        string  `json:"state"`
	Loss         float64 `json:"loss"`
}

// Paths returns a read-only snapshot of every registered path (telemetry).
func (s *Scheduler) Paths() []PathInfo {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]PathInfo, 0, len(s.paths))
	for _, p := range s.paths {
		out = append(out, PathInfo{
			ID:           p.id,
			CapacityMbps: p.capacity,
			State:        p.state.String(),
			Loss:         p.loss,
		})
	}
	return out
}

// New builds a scheduler from options.
func New(opts Options) *Scheduler {
	if opts.Mode == "" {
		opts.Mode = ModeLB
	}
	if opts.Affinity == "" {
		opts.Affinity = AffPacket
	}
	if opts.BalanceBy == "" {
		opts.BalanceBy = ByCapacity
	}
	return &Scheduler{opts: opts, byID: make(map[string]*path), rng: rand.New(rand.NewSource(1))}
}

// AddPath registers a WAN with its effective capacity (mbps). Idempotent.
func (s *Scheduler) AddPath(id string, capacityMbps float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; ok {
		s.byID[id].capacity = capacityMbps
		return
	}
	p := &path{id: id, capacity: capacityMbps, state: health.StateHealthy}
	s.paths = append(s.paths, p)
	s.byID[id] = p
	s.ringVer++
}

// RemovePath drops a path (e.g. session expiry).
func (s *Scheduler) RemovePath(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[id]; !ok {
		return
	}
	delete(s.byID, id)
	for i, p := range s.paths {
		if p.id == id {
			s.paths = append(s.paths[:i], s.paths[i+1:]...)
			break
		}
	}
	s.ringVer++
}

// OnState updates a path's circuit-breaker state and loss estimate.
func (s *Scheduler) OnState(id string, st health.State, loss float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.byID[id]; ok {
		p.state = st
		p.loss = loss
		s.ringVer++
	}
}

// Pick returns the WAN ID for the next frame. ok=false when no WAN is usable
// (all down); callers should drop the frame and log.
func (s *Scheduler) Pick(f *frame.Frame) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	usable := s.usableLocked()
	if len(usable) == 0 {
		return "", false
	}
	if s.opts.Mode == ModeStandby {
		// Strict hierarchy HEALTHY > DEGRADED > DOWN: the standby must
		// abandon a degraded active path (loss beyond FEC capacity)
		// immediately, not wait for a hard failure — otherwise the whole
		// point of near-zero-loss failover is lost.
		for _, p := range usable {
			if p.state == health.StateHealthy {
				return p.id, true
			}
		}
		return usable[0].id, true // all degraded: drain on the least-bad (config order)
	}
	if s.opts.Affinity == AffFlow {
		if h, ok := parseInnerHash(f.Payload); ok {
			return s.pickRingLocked(h, usable), true
		}
	}
	return s.pickWeightedLocked(usable), true
}

// PickWRR returns the next WAN for cross-path FEC (docs/DESIGN.md §6.4):
// the frames of one block are spread across ALL usable WANs, so a
// whole-WAN failure costs only its share of each block — recoverable when
// the cross-path redundancy covers it. Smooth weighted round-robin: each
// path accumulates its weight and the max is picked, which interleaves the
// paths proportionally to capacity while guaranteeing the same path is
// never chosen twice in a row while another usable path exists.
func (s *Scheduler) PickWRR() (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	usable := s.usableLocked()
	if len(usable) == 0 {
		return "", false
	}
	total := 0.0
	best := usable[0]
	for _, p := range usable {
		w := s.weightLocked(p)
		p.rr += w
		total += w
		if p.rr > best.rr {
			best = p
		}
	}
	if total <= 0 {
		return best.id, true // all zero-weight (degraded-only): drain in order
	}
	best.rr -= total
	return best.id, true
}

// Healthy reports whether at least one WAN is usable.
func (s *Scheduler) Healthy() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.usableLocked()) > 0
}

// usableLocked returns paths that can carry traffic, in config order.
func (s *Scheduler) usableLocked() []*path {
	out := make([]*path, 0, len(s.paths))
	for _, p := range s.paths {
		if p.state != health.StateDown {
			out = append(out, p)
		}
	}
	return out
}

// weightLocked returns a path's scheduling weight.
func (s *Scheduler) weightLocked(p *path) float64 {
	switch p.state {
	case health.StateDown:
		return 0
	case health.StateDegraded:
		return weightDegraded
	}
	w := p.capacity
	if s.opts.BalanceBy == ByRound || w <= 0 {
		return 1
	}
	return w
}

// pickWeightedLocked picks a path weighted by capacity (degraded paths get
// a token weight, so they drain instead of being cut abruptly).
func (s *Scheduler) pickWeightedLocked(usable []*path) string {
	total := 0.0
	for _, p := range usable {
		total += s.weightLocked(p)
	}
	if total <= 0 {
		return usable[0].id // all zero-weight (degraded-only): keep them draining
	}
	r := s.rng.Float64() * total
	for _, p := range usable {
		r -= s.weightLocked(p)
		if r <= 0 {
			return p.id
		}
	}
	return usable[len(usable)-1].id
}

// pickRingLocked picks via consistent hashing over the usable set. The ring
// is rebuilt lazily when the usable set changes (ringVer), so healthy paths
// keep their flows across unrelated changes (only flows of a removed path
// migrate).
func (s *Scheduler) pickRingLocked(h uint64, usable []*path) string {
	if s.ring == nil || s.lastRingVer != s.ringVer {
		buildRing(s, usable)
	}
	i := sort.Search(len(s.ring), func(i int) bool { return s.ring[i] >= uint32(h) })
	if i == len(s.ring) {
		i = 0
	}
	return s.ringPaths[s.ring[i]]
}

// buildRing places 64 virtual nodes per path on a 2^32 ring.
func buildRing(s *Scheduler, usable []*path) {
	ring := make([]uint32, 0, 64*len(usable))
	paths := make(map[uint32]string, 64*len(usable))
	for _, p := range usable {
		for v := 0; v < 64; v++ {
			node := fnv1a(p.id, uint32(v))
			ring = append(ring, node)
			paths[node] = p.id
		}
	}
	sort.Slice(ring, func(i, j int) bool { return ring[i] < ring[j] })
	s.ring = ring
	s.ringPaths = paths
	s.lastRingVer = s.ringVer
}

// fnv1a hashes the path id mixed with a virtual-node index (FNV-1a 32-bit).
func fnv1a(id string, v uint32) uint32 {
	h := uint32(2166136261)
	for i := 0; i < len(id); i++ {
		h ^= uint32(id[i])
		h *= 16777619
	}
	h ^= v
	h *= 16777619
	return h
}

// parseInnerHash hashes the inner datagram's 4-tuple (IPv4 UDP/TCP) so
// flow-affinity keeps one connection on one WAN. Returns ok=false when the
// payload is not a parseable IPv4 packet — the caller then falls back to
// packet-level picking.
func parseInnerHash(payload []byte) (uint64, bool) {
	if len(payload) < 20 {
		return 0, false
	}
	if payload[0]>>4 != 4 { // IPv4 only (IPv6: fall back to packet pick)
		return 0, false
	}
	ihl := int(payload[0]&0x0f) * 4
	if ihl < 20 || len(payload) < ihl {
		return 0, false
	}
	proto := payload[9]
	// 4-tuple: src IP (4) + dst IP (4) + src port (2) + dst port (2).
	base := uint64(binary.BigEndian.Uint32(payload[12:16]))<<32 |
		uint64(binary.BigEndian.Uint32(payload[16:20]))
	if (proto == 6 || proto == 17) && len(payload) >= ihl+4 {
		base ^= uint64(binary.BigEndian.Uint16(payload[ihl:ihl+2])) << 16
		base ^= uint64(binary.BigEndian.Uint16(payload[ihl+2 : ihl+4]))
	}
	return base, true
}
