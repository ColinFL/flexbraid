package tunnel

// Telemetry types (M5.1). Snapshots are plain value structs with JSON tags,
// safe to marshal straight into an HTTP response or a structured log line.

import (
	"strings"
	"time"
)

// WANStats is one path's runtime state (client or server side).
type WANStats struct {
	ID           string  `json:"id"`
	Transport    string  `json:"transport"`      // udp | faketcp | icmp
	State        string  `json:"state"`          // healthy | degraded | down
	LossPct      float64 `json:"loss_pct"`       // EWMA loss, %
	RTTMs        float64 `json:"rtt_ms"`         // EWMA round-trip, ms
	JitterMs     float64 `json:"jitter_ms"`      // EWMA jitter, ms
	CapacityMbps float64 `json:"capacity_mbps"`  // declared capacity
	FramesSent   uint64  `json:"frames_sent"`    // data frames handed to the transport
	Pongs        uint64  `json:"pongs"`          // answered probes
	MissedProbes uint64  `json:"missed_probes"`  // unanswered probes
	LastRxAgeMs  int64   `json:"last_rx_age_ms"` // age of last VALID inbound frame, ms
	QueueDrops   uint64  `json:"queue_drops"`    // frames dropped by the bounded send queue (§7.6)
}

// FECStats aggregates forward-error-correction counters.
type FECStats struct {
	CrossPath  bool   `json:"cross_path"`
	DataShards int    `json:"data_shards"`
	BlocksSent uint64 `json:"blocks_sent"`
	FramesLost uint64 `json:"frames_lost"` // unrecoverable, summed over paths
	Recovered  uint64 `json:"recovered"`   // data frames rebuilt from parity
	CodingOn   bool   `json:"coding_on"`   // encoder currently emits parity
}

// DeliveryStats describes the in-order reassembly window.
type DeliveryStats struct {
	Pending    int    `json:"pending"`
	MaxPending int    `json:"max_pending"`
	Drops      uint64 `json:"drops"` // BDP-guard drop-oldest count
}

// Snapshot is the full telemetry payload for one endpoint.
type Snapshot struct {
	Time      string        `json:"time"` // RFC3339 UTC
	Mode      string        `json:"mode"` // client | server
	UptimeSec float64       `json:"uptime_sec"`
	Sessions  int           `json:"sessions"` // server only (active sessions)
	WANs      []WANStats    `json:"wans"`
	FEC       FECStats      `json:"fec"`
	Delivery  DeliveryStats `json:"delivery"`
}

// Snapshot returns a point-in-time telemetry snapshot of the client.
func (c *Client) Snapshot() Snapshot {
	s := Snapshot{
		Time:      time.Now().UTC().Format(time.RFC3339),
		Mode:      "client",
		UptimeSec: time.Since(c.start).Seconds(),
		WANs:      make([]WANStats, 0, len(c.wans)),
	}
	var blocks, lost, recv uint64
	var codingOn bool
	for _, wan := range c.wans {
		w := WANStats{
			ID:           wan.id,
			Transport:    string(wan.cfg.Transport),
			State:        wan.health.State().String(),
			LossPct:      wan.health.Loss() * 100,
			RTTMs:        float64(wan.health.RTT()) / float64(time.Millisecond),
			JitterMs:     float64(wan.health.Jitter()) / float64(time.Millisecond),
			CapacityMbps: float64(wan.cfg.CapacityMbps),
			FramesSent:   wan.framesSent.Load(),
			Pongs:        wan.pongs.Load(),
			MissedProbes: wan.missedProbes.Load(),
		}
		if last := wan.lastRx.Load(); last > 0 {
			w.LastRxAgeMs = time.Since(time.Unix(0, last)).Milliseconds()
		}
		if wan.q != nil {
			_, _, w.QueueDrops = wan.q.stats()
		}
		s.WANs = append(s.WANs, w)
	}
	if c.crossPath {
		blocks = c.xenc.Stats()
		l, r := c.xdec.Stats()
		lost, recv = l, r
		blocks += 0
	} else {
		for _, wan := range c.wans {
			blocks += wan.enc.Stats()
			l, r := wan.dec.Stats()
			lost += l
			recv += r
			if wan.enc.CodingOn() {
				codingOn = true
			}
		}
	}
	s.FEC = FECStats{
		CrossPath:  c.crossPath,
		DataShards: c.cfg.FEC.DataShards,
		BlocksSent: blocks,
		FramesLost: lost,
		Recovered:  recv,
		CodingOn:   codingOn || c.crossPath,
	}
	s.Delivery = DeliveryStats{
		Pending:    c.delivery.pendingCount(),
		MaxPending: c.delivery.maxPending,
		Drops:      c.delivery.dropsTotal(),
	}
	return s
}

// Snapshot returns a point-in-time telemetry snapshot of the server. WAN
// entries are aggregated per unique path across all sessions; session state
// is the source of truth for path health.
func (s *Server) Snapshot() Snapshot {
	snap := Snapshot{
		Time:      time.Now().UTC().Format(time.RFC3339),
		Mode:      "server",
		UptimeSec: time.Since(s.start).Seconds(),
	}
	s.statesMu.Lock()
	snap.Sessions = len(s.states)
	seen := make(map[string]bool, 8)
	snap.WANs = make([]WANStats, 0, len(s.states))
	// Aggregate scheduler path info per path key across sessions.
	pathState := make(map[string]string) // key -> state string
	byKey := make(map[string]WANStats)
	for _, st := range s.states {
		for k := range st.paths {
			if seen[k] {
				continue
			}
			seen[k] = true
			w := WANStats{ID: k}
			// scheduler carries capacity/state/loss; take the richest.
			for _, pi := range st.sched.Paths() {
				if strings.Contains(k, pi.ID) || pi.ID == k {
					w.CapacityMbps = pi.CapacityMbps
					w.State = pi.State
					if pi.Loss > 0 {
						w.LossPct = pi.Loss * 100
					}
				}
			}
			byKey[k] = w
		}
	}
	_ = pathState
	for _, w := range byKey {
		snap.WANs = append(snap.WANs, w)
	}
	s.statesMu.Unlock()

	lost, recv := s.fecDec.Stats()
	snap.FEC = FECStats{
		CrossPath:  strings.EqualFold(string(s.cfg.FEC.Mode), "crosspath"),
		DataShards: s.cfg.FEC.DataShards,
		BlocksSent: 0, // server has no per-block encoder count exposed
		FramesLost: lost,
		Recovered:  recv,
		CodingOn:   true,
	}
	return snap
}
