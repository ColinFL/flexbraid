// Package config loads and validates FlexBraid configuration.
//
// FlexBraid is a multi-WAN bonding tunnel: it weaves several physical
// uplinks ("WANs") into a single logical link so that an inner VPN such as
// WireGuard sees one stable connection. This package defines the full
// configuration surface — WAN list with per-path bandwidth and transport,
// the scheduler, forward error correction (which can be switched off
// entirely) and the health/circuit-breaker tuning.
package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Mode identifies whether this instance is the tunnel client or server.
type Mode string

const (
	ModeClient Mode = "client"
	ModeServer Mode = "server"
)

// SchedulerMode selects how traffic is spread across WANs.
type SchedulerMode string

const (
	// SchedulerLB actively load-balances traffic across all healthy WANs.
	SchedulerLB SchedulerMode = "lb"
	// SchedulerStandby keeps the highest-priority WAN active and the rest as
	// warm standbys (near-zero-loss failover, no load splitting).
	SchedulerStandby SchedulerMode = "standby"
)

// BalanceBy selects the metric used to weight load balancing.
type BalanceBy string

const (
	// BalanceByCapacity weights paths by their declared capacity_mbps.
	BalanceByCapacity BalanceBy = "capacity"
	// BalanceByFEC weights by the residual capacity after FEC overhead.
	BalanceByFEC BalanceBy = "fec"
	// BalanceByRoundRobin ignores weights and rotates evenly.
	BalanceByRoundRobin BalanceBy = "roundrobin"
)

// Affinity selects the scheduling granularity.
type Affinity string

const (
	// AffinityFlow keeps each inner flow on one WAN (no intra-connection
	// reordering; per-WAN FEC coherent). Default.
	AffinityFlow Affinity = "flow"
	// AffinityPacket distributes frames packet-by-packet (aggregate throughput;
	// requires the delivery buffer; pairs with cross-path FEC).
	AffinityPacket Affinity = "packet"
)

// DropPolicy selects what happens when a WAN send queue overflows.
type DropPolicy string

const (
	// DropOldest drops the oldest queued frame (TCP learns to back off).
	DropOldest DropPolicy = "drop-oldest"
	// DropNewest drops the newest frame (real-time UDP wants latest state).
	DropNewest DropPolicy = "drop-newest"
)

// Queue configures the bounded per-WAN send queue and rate limiting.
type Queue struct {
	MaxPkts       int        `yaml:"max_pkts"`        // bounded queue depth (BDP-aware)
	RateLimitMbps float64    `yaml:"rate_limit_mbps"` // 0 = no explicit limiter (use capacity_mbps)
	Drop          DropPolicy `yaml:"drop"`            // on overflow
}

// FECMode controls how forward error correction behaves.
type FECMode string

const (
	// FECAdaptive adjusts redundancy from measured loss (recommended).
	FECAdaptive FECMode = "adaptive"
	// FECFixed keeps a constant configured overhead.
	FECFixed FECMode = "fixed"
	// FECOff is an explicit override; equivalent to fec.enabled=false.
	FECOff FECMode = "off"
	// FECCrosspath codes erasure blocks across all WANs (survives whole-WAN
	// loss at capacity cost). Only valid with affinity: packet.
	FECCrosspath FECMode = "crosspath"
)

// TransportMode is the wire format used on a single WAN.
type TransportMode string

const (
	// TransportUDP is plain encrypted UDP.
	TransportUDP TransportMode = "udp"
	// TransportFakeTCP disguises the tunnel as TCP to bypass UDP blocking/QoS.
	TransportFakeTCP TransportMode = "faketcp"
	// TransportICMP tunnels over ICMP echo (last resort for UDP-blocked links).
	TransportICMP TransportMode = "icmp"
)

// Config is the root configuration document.
type Config struct {
	Mode      Mode   `yaml:"mode"`
	Listen    string `yaml:"listen"`
	Server    string `yaml:"server"`
	SessionID string `yaml:"session_id"` // auto | <hex> (server keys sessions by this, not source IP)
	Scheduler Sched  `yaml:"scheduler"`
	FEC       FEC    `yaml:"fec"`
	MTU       int    `yaml:"mtu"` // inner MTU advertised to WireGuard (default 1420)
	WANs      []WAN  `yaml:"wans"`
	Health    Health `yaml:"health"`
	Crypto    Crypto `yaml:"crypto"`
	Log       Log    `yaml:"log"`
}

// Sched configures the packet scheduler / load balancer.
type Sched struct {
	Mode      SchedulerMode `yaml:"mode"`
	Affinity  Affinity      `yaml:"affinity"` // flow (default) | packet
	BalanceBy BalanceBy     `yaml:"balance_by"`
	Queue     Queue         `yaml:"queue"`
}

// FEC configures forward error correction. It can be fully disabled.
type FEC struct {
	Enabled          bool    `yaml:"enabled"`
	Mode             FECMode `yaml:"mode"`
	MaxLossPct       float64 `yaml:"max_loss_pct"`       // compensable loss % per path
	BlockTimeoutMS   int     `yaml:"block_timeout_ms"`   // block collection window (adds latency)
	FixedOverheadPct float64 `yaml:"fixed_overhead_pct"` // overhead used when mode=fixed
}

// WAN describes one physical uplink / path.
type WAN struct {
	ID            string        `yaml:"id"`
	Transport     TransportMode `yaml:"transport"`
	Iface         string        `yaml:"iface"`            // bind device (optional, improves perf)
	CapacityMbps  int           `yaml:"capacity_mbps"`    // declared bandwidth, used by balance_by=capacity
	Weight        float64       `yaml:"weight"`           // manual multiplier (default 1.0)
	FECMaxLossPct *float64      `yaml:"fec_max_loss_pct"` // per-path FEC override (nil = global)
}

// Health tunes path monitoring and the circuit breaker.
type Health struct {
	LossAlphaFast float64 `yaml:"loss_alpha_fast"` // fast-rise EWMA weight (reacts to spikes)
	LossAlphaSlow float64 `yaml:"loss_alpha_slow"` // slow-decay EWMA weight (settles down)
	JitterAlpha   float64 `yaml:"jitter_alpha"`
	DegradeSec    int     `yaml:"degrade_sec"`    // sustained loss above cap -> DEGRADED
	RecoverMin    int     `yaml:"recover_min"`    // stability window before a path is restored
	ProbeInterval int     `yaml:"probe_interval"` // active keepalive period while DOWN
	DownGraceSec  int     `yaml:"down_grace_sec"` // drain window before hard disable
}

// Crypto configures the tunnel's encryption/auth.
type Crypto struct {
	Key           string `yaml:"key"`            // shared PSK; AEAD keys derived from it (required)
	Cipher        string `yaml:"cipher"`         // chacha20poly1305 | aes256gcm
	IntegrityOnly bool   `yaml:"integrity_only"` // Poly1305 MAC over plaintext instead of full AEAD (WG already encrypts inner data)
}

// Log controls logging.
type Log struct {
	Level string `yaml:"level"` // debug|info|warn|error
	File  string `yaml:"file"`
}

// Load reads and parses a YAML config file, then validates it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate checks invariants and applies defaults.
func (c *Config) Validate() error {
	if c.Mode == "" {
		c.Mode = ModeClient
	}
	if c.Mode != ModeClient && c.Mode != ModeServer {
		return fmt.Errorf("invalid mode %q: must be %q or %q", c.Mode, ModeClient, ModeServer)
	}
	if c.Listen == "" {
		return fmt.Errorf("listen address is required")
	}
	if c.Mode == ModeClient && c.Server == "" {
		return fmt.Errorf("server address is required in client mode")
	}
	if c.SessionID == "" {
		c.SessionID = "auto"
	}

	if c.Scheduler.Mode == "" {
		c.Scheduler.Mode = SchedulerLB
	}
	switch c.Scheduler.Mode {
	case SchedulerLB, SchedulerStandby:
	default:
		return fmt.Errorf("invalid scheduler.mode %q: must be %q or %q", c.Scheduler.Mode, SchedulerLB, SchedulerStandby)
	}
	if c.Scheduler.Affinity == "" {
		c.Scheduler.Affinity = AffinityFlow
	}
	switch c.Scheduler.Affinity {
	case AffinityFlow, AffinityPacket:
	default:
		return fmt.Errorf("invalid scheduler.affinity %q: must be %q or %q", c.Scheduler.Affinity, AffinityFlow, AffinityPacket)
	}
	if c.Scheduler.BalanceBy == "" {
		c.Scheduler.BalanceBy = BalanceByCapacity
	}
	if c.Scheduler.Queue.MaxPkts == 0 {
		c.Scheduler.Queue.MaxPkts = 1024
	}
	if c.Scheduler.Queue.Drop == "" {
		c.Scheduler.Queue.Drop = DropOldest
	}
	switch c.Scheduler.Queue.Drop {
	case DropOldest, DropNewest:
	default:
		return fmt.Errorf("invalid scheduler.queue.drop %q: must be %q or %q", c.Scheduler.Queue.Drop, DropOldest, DropNewest)
	}

	if c.MTU == 0 {
		c.MTU = 1420
	}
	if c.MTU < 576 || c.MTU > 9000 {
		return fmt.Errorf("mtu must be in [576,9000], got %d", c.MTU)
	}

	// FEC defaults + explicit disable handling.
	if c.FEC.Mode == FECOff {
		c.FEC.Enabled = false
	}
	if c.FEC.Enabled {
		if c.FEC.Mode == "" {
			c.FEC.Mode = FECAdaptive
		}
		switch c.FEC.Mode {
		case FECAdaptive, FECFixed, FECCrosspath:
		default:
			return fmt.Errorf("invalid fec.mode %q", c.FEC.Mode)
		}
		if c.FEC.Mode == FECCrosspath && c.Scheduler.Affinity != AffinityPacket {
			return fmt.Errorf("fec.mode=crosspath requires scheduler.affinity=packet")
		}
		if c.FEC.MaxLossPct < 0 || c.FEC.MaxLossPct > 90 {
			return fmt.Errorf("fec.max_loss_pct must be in [0,90], got %v", c.FEC.MaxLossPct)
		}
		if c.FEC.BlockTimeoutMS <= 0 {
			c.FEC.BlockTimeoutMS = 8
		}
	}

	if len(c.WANs) == 0 {
		return fmt.Errorf("at least one WAN is required")
	}
	seen := map[string]bool{}
	for i := range c.WANs {
		w := &c.WANs[i]
		if w.ID == "" {
			w.ID = "wan" + strconv.Itoa(i+1)
		}
		if seen[w.ID] {
			return fmt.Errorf("duplicate WAN id %q", w.ID)
		}
		seen[w.ID] = true
		if w.Transport == "" {
			w.Transport = TransportUDP
		}
		switch w.Transport {
		case TransportUDP, TransportFakeTCP, TransportICMP:
		default:
			return fmt.Errorf("WAN %q: invalid transport %q", w.ID, w.Transport)
		}
		if w.Weight == 0 {
			w.Weight = 1.0
		}
		if w.CapacityMbps < 0 {
			return fmt.Errorf("WAN %q: capacity_mbps cannot be negative", w.ID)
		}
	}

	if c.Health.LossAlphaFast == 0 {
		c.Health.LossAlphaFast = 0.4
	}
	if c.Health.LossAlphaSlow == 0 {
		c.Health.LossAlphaSlow = 0.03
	}
	if c.Health.JitterAlpha == 0 {
		c.Health.JitterAlpha = 0.1
	}
	if c.Health.DegradeSec == 0 {
		c.Health.DegradeSec = 3
	}
	if c.Health.RecoverMin == 0 {
		c.Health.RecoverMin = 2
	}
	if c.Health.ProbeInterval == 0 {
		c.Health.ProbeInterval = 5
	}

	if c.Crypto.Key == "" {
		return fmt.Errorf("crypto.key (shared PSK) is required")
	}
	if c.Crypto.Cipher == "" {
		c.Crypto.Cipher = "chacha20poly1305"
	}

	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	return nil
}
