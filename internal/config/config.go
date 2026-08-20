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
	"bytes"
	"fmt"
	"net"
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

// FECMode controls how forward error correction behaves.
type FECMode string

const (
	// FECAdaptive is the default mode: redundancy is sized live from the
	// health monitor's measured loss (docs/DESIGN.md §6), with pass-through
	// on clean links (no latency, no overhead) and coding scaled up as loss
	// appears.
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
	Mode      Mode      `yaml:"mode"`
	Listen    string    `yaml:"listen"`
	Server    string    `yaml:"server"`
	WGPeer    string    `yaml:"wg_peer"`    // server mode: inner WireGuard peer (egress)
	SessionID string    `yaml:"session_id"` // auto | <hex> (server keys sessions by this, not source IP)
	Scheduler Sched     `yaml:"scheduler"`
	FEC       FEC       `yaml:"fec"`
	MTU       int       `yaml:"mtu"` // inner MTU advertised to WireGuard (default 1420)
	WANs      []WAN     `yaml:"wans"`
	Delivery  Delivery  `yaml:"delivery"`
	Health    Health    `yaml:"health"`
	Crypto    Crypto    `yaml:"crypto"`
	Log       Log       `yaml:"log"`
	Telemetry Telemetry `yaml:"telemetry"`
	Queue     Queue     `yaml:"queue"`

	// Transport is the server-side wire format ("udp" default | "faketcp").
	// Clients pick a per-WAN transport instead (wans[].transport).
	Transport TransportMode `yaml:"transport"`
}

// Sched configures the packet scheduler / load balancer.
type Sched struct {
	Mode      SchedulerMode `yaml:"mode"`
	Affinity  Affinity      `yaml:"affinity"` // flow (default) | packet
	BalanceBy BalanceBy     `yaml:"balance_by"`
	// CapacityCapMbps clamps the capacity a client may *declare* to the
	// server (server-side trust boundary: the declared weight is
	// untrusted input). 0 = no cap.
	CapacityCapMbps float64 `yaml:"capacity_cap_mbps"`
}

// Delivery tunes the in-order reassembly window on the client.
type Delivery struct {
	// GapTimeoutMS bounds head-of-line blocking: a missing seq stalls
	// delivery for at most this long, then the hole is skipped. Must
	// cover the path RTT skew in packet-affinity mode (cable+LTE mixes
	// routinely need 100ms+). Default 100.
	GapTimeoutMS int `yaml:"gap_timeout_ms"`
	// MaxPending caps the reorder buffer (BDP guard): frames beyond the
	// cap are dropped oldest-first, so a stalled path cannot grow the
	// buffer without bound. Default 4096.
	MaxPending int `yaml:"max_pending"`
}

// FEC configures forward error correction. It can be fully disabled.
type FEC struct {
	Enabled          bool    `yaml:"enabled"`
	Mode             FECMode `yaml:"mode"`
	DataShards       int     `yaml:"data_shards"`        // data frames per block (default 10; games: 4–6)
	MaxLossPct       float64 `yaml:"max_loss_pct"`       // redundancy ceiling (adaptive) / fixed target (fixed)
	BlockTimeoutMS   int     `yaml:"block_timeout_ms"`   // block collection window (adds latency when coding)
	FixedOverheadPct float64 `yaml:"fixed_overhead_pct"` // overhead used when mode=fixed

	// Adaptive thresholds (mode: adaptive): coding switches ON when the
	// measured path loss reaches AdaptMinLossPct and OFF below
	// AdaptResumePct after at least AdaptHoldSec — so a clean link runs
	// pass-through (zero latency/overhead) and coding only engages when
	// there is actually something to repair.
	AdaptMinLossPct float64 `yaml:"adapt_min_loss_pct"` // default 2
	AdaptResumePct  float64 `yaml:"adapt_resume_pct"`   // default 0.5
	AdaptHoldSec    float64 `yaml:"adapt_hold_sec"`     // default 10

	// ProtectionLevel (mode: crosspath only) is the redundancy floor as a
	// fraction of data shards: 0.4 → at least ceil(k·0.4) parity shards per
	// block regardless of the measured loss, so a whole-WAN failure loses
	// at most (1 − protection) of every block. 1.0 doubles the wire
	// traffic and survives the loss of any single WAN in a two-WAN setup.
	// Default 0.5.
	ProtectionLevel float64 `yaml:"protection_level"`
}

// WAN describes one physical uplink / path.
type WAN struct {
	ID            string        `yaml:"id"`
	Transport     TransportMode `yaml:"transport"`
	Iface         string        `yaml:"iface"`            // bind device (SO_BINDTODEVICE on Linux; requires privilege)
	LocalIP       string        `yaml:"local_ip"`         // bind source address (fallback when iface bind is denied)
	FIB           int           `yaml:"fib"`              // FreeBSD routing table (SO_SETFIB); -1 = unset, needs net.fibs>1
	CapacityMbps  int           `yaml:"capacity_mbps"`    // declared bandwidth, used by balance_by=capacity
	Weight        float64       `yaml:"weight"`           // manual multiplier (default 1.0)
	FECMaxLossPct *float64      `yaml:"fec_max_loss_pct"` // per-path FEC override (nil = global)
}

// Health tunes path monitoring and the circuit breaker.
type Health struct {
	LossAlphaFast   float64 `yaml:"loss_alpha_fast"` // fast-rise EWMA weight (reacts to spikes)
	LossAlphaSlow   float64 `yaml:"loss_alpha_slow"` // slow-decay EWMA weight (settles down)
	JitterAlpha     float64 `yaml:"jitter_alpha"`
	DegradeSec      float64 `yaml:"degrade_sec"`       // sustained loss above cap -> DEGRADED (s)
	RecoverMin      float64 `yaml:"recover_min"`       // stability window (min, fractional ok) before a path is restored
	ProbeInterval   float64 `yaml:"probe_interval"`    // keepalive probe period (s); 0 -> 1s
	DownAfterMisses int     `yaml:"down_after_misses"` // consecutive unanswered probes -> DOWN (default 3)
	DownGraceSec    float64 `yaml:"down_grace_sec"`    // debounce before the DOWN transition (s); 0 = immediate
}

// Crypto configures the tunnel's encryption/auth.
type Crypto struct {
	Key    string `yaml:"key"`    // shared PSK; AEAD keys derived from it (required)
	Cipher string `yaml:"cipher"` // chacha20poly1305 | aes256gcm
}

// Log controls logging.
type Log struct {
	Level string `yaml:"level"` // debug|info|warn|error
	File  string `yaml:"file"`
}

// Telemetry exposes runtime stats (M5.1). Both knobs default to off so a
// firewall box stays quiet unless the operator opts in.
type Telemetry struct {
	// Listen enables an HTTP server exposing the JSON snapshot at Path
	// (default "/stats"). Empty = off. Recommend binding to a loopback or
	// management address only — the endpoint has no auth.
	Listen string `yaml:"listen"`
	// Path is the HTTP path for the JSON snapshot (default "/stats").
	Path string `yaml:"path"`
	// IntervalSec > 0 logs the JSON snapshot periodically via slog
	// (structured log, key "telemetry"). 0 = off.
	IntervalSec float64 `yaml:"interval_sec"`
}

// Queue tunes the bounded per-WAN send queue (docs/DESIGN.md §7.6).
type Queue struct {
	// Enabled turns on the bounded queue + token-bucket rate limiter
	// (nil/absent = default true). WireGuard has no congestion control, so
	// without this a fast WAN can bufferbloat a slow one and memory grows
	// without bound.
	Enabled *bool `yaml:"enabled"`
	// MaxBytes bounds each WAN's outbound queue (BDP-ish memory guard),
	// default 262144 (256 KiB).
	MaxBytes int `yaml:"max_bytes"`
	// Drop is the overflow policy: "oldest" (default — drop the longest
	// buffered frame; TCP-ish flows want the newest bytes) or "newest"
	// (drop the just-arrived frame; real-time UDP wants the latest state).
	Drop string `yaml:"drop"`
	// RateLimit gates the consumer to wans[].capacity_mbps via a token
	// bucket (default true).
	RateLimit bool `yaml:"rate_limit"`
}

// Load reads and parses a YAML config file, then validates it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var c Config
	// KnownFields: a typo'd key is a hard error, not a silently ignored
	// knob — FlexBraid's config surface is the product.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
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
		return fmt.Errorf("client requires server address")
	}
	if c.Mode == ModeServer && c.WGPeer == "" {
		return fmt.Errorf("server requires wg_peer (inner WireGuard peer address)")
	}
	// Addresses must parse, or Start() would have to panic.
	if _, err := net.ResolveUDPAddr("udp", c.Listen); err != nil {
		return fmt.Errorf("invalid listen address %q: %w", c.Listen, err)
	}
	if c.Mode == ModeClient {
		if _, err := net.ResolveUDPAddr("udp", c.Server); err != nil {
			return fmt.Errorf("invalid server address %q: %w", c.Server, err)
		}
	}
	if c.Mode == ModeServer {
		if _, err := net.ResolveUDPAddr("udp", c.WGPeer); err != nil {
			return fmt.Errorf("invalid wg_peer address %q: %w", c.WGPeer, err)
		}
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
		// Packet is the default: the primary inner payload is a single
		// WireGuard flow, which flow-affinity would pin to one WAN and
		// defeat load balancing entirely. Flow affinity exists for many
		// independent inner flows (e.g. OpenVPN).
		c.Scheduler.Affinity = AffinityPacket
	}
	switch c.Scheduler.Affinity {
	case AffinityFlow, AffinityPacket:
	default:
		return fmt.Errorf("invalid scheduler.affinity %q: must be %q or %q", c.Scheduler.Affinity, AffinityFlow, AffinityPacket)
	}
	if c.Scheduler.BalanceBy == "" {
		c.Scheduler.BalanceBy = BalanceByCapacity
	}
	if c.Scheduler.CapacityCapMbps < 0 {
		return fmt.Errorf("scheduler.capacity_cap_mbps cannot be negative")
	}

	if c.Delivery.GapTimeoutMS == 0 {
		c.Delivery.GapTimeoutMS = 100
	}
	if c.Delivery.GapTimeoutMS < 10 || c.Delivery.GapTimeoutMS > 5000 {
		return fmt.Errorf("delivery.gap_timeout_ms must be in [10,5000], got %d", c.Delivery.GapTimeoutMS)
	}
	if c.Delivery.MaxPending == 0 {
		c.Delivery.MaxPending = 4096
	}
	if c.Delivery.MaxPending < 64 || c.Delivery.MaxPending > 1<<20 {
		return fmt.Errorf("delivery.max_pending must be in [64,1048576], got %d", c.Delivery.MaxPending)
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
		if c.FEC.DataShards == 0 {
			c.FEC.DataShards = 10
		}
		if c.FEC.DataShards < 2 || c.FEC.DataShards > 64 {
			return fmt.Errorf("fec.data_shards must be in [2,64], got %d", c.FEC.DataShards)
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
		if c.FEC.AdaptMinLossPct == 0 {
			c.FEC.AdaptMinLossPct = 2
		}
		if c.FEC.AdaptResumePct == 0 {
			c.FEC.AdaptResumePct = 0.5
		}
		if c.FEC.AdaptHoldSec == 0 {
			c.FEC.AdaptHoldSec = 10
		}
		if c.FEC.AdaptMinLossPct <= 0 || c.FEC.AdaptMinLossPct > 90 {
			return fmt.Errorf("fec.adapt_min_loss_pct must be in (0,90], got %v", c.FEC.AdaptMinLossPct)
		}
		if c.FEC.AdaptResumePct < 0 || c.FEC.AdaptResumePct >= c.FEC.AdaptMinLossPct {
			return fmt.Errorf("fec.adapt_resume_pct must be in [0, adapt_min_loss_pct), got %v", c.FEC.AdaptResumePct)
		}
		if c.FEC.AdaptHoldSec < 0 || c.FEC.AdaptHoldSec > 3600 {
			return fmt.Errorf("fec.adapt_hold_sec must be in [0,3600], got %v", c.FEC.AdaptHoldSec)
		}
		if c.FEC.Mode == FECFixed && (c.FEC.FixedOverheadPct <= 0 || c.FEC.FixedOverheadPct > 200) {
			return fmt.Errorf("fec.fixed_overhead_pct must be in (0,200], got %v", c.FEC.FixedOverheadPct)
		}
		if c.FEC.Mode == FECCrosspath {
			if c.FEC.ProtectionLevel == 0 {
				c.FEC.ProtectionLevel = 0.5
			}
			if c.FEC.ProtectionLevel < 0 || c.FEC.ProtectionLevel > 1 {
				return fmt.Errorf("fec.protection_level must be in [0,1], got %v", c.FEC.ProtectionLevel)
			}
		}
	}

	if len(c.WANs) == 0 {
		if c.Mode == ModeClient {
			return fmt.Errorf("client requires at least one WAN")
		}
		// server mode: M1 binds its own WAN transport internally
	}
	if c.Mode == ModeServer {
		if c.Transport == "" {
			c.Transport = TransportUDP
		}
		switch c.Transport {
		case TransportUDP, TransportFakeTCP, TransportICMP:
		default:
			return fmt.Errorf("server transport %q not supported (udp | faketcp | icmp)", c.Transport)
		}
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
		c.Health.ProbeInterval = 1
	}
	if c.Health.DownAfterMisses == 0 {
		c.Health.DownAfterMisses = 3
	}
	if c.Health.DownAfterMisses < 1 || c.Health.DownAfterMisses > 32 {
		return fmt.Errorf("health.down_after_misses must be in [1,32], got %d", c.Health.DownAfterMisses)
	}
	if c.Health.DownGraceSec < 0 || c.Health.DownGraceSec > 60 {
		return fmt.Errorf("health.down_grace_sec must be in [0,60], got %v", c.Health.DownGraceSec)
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
	if c.Telemetry.Path == "" {
		c.Telemetry.Path = "/stats"
	}
	if c.Telemetry.IntervalSec < 0 {
		return fmt.Errorf("telemetry.interval_sec must be >= 0, got %v", c.Telemetry.IntervalSec)
	}
	if c.Telemetry.Listen != "" {
		if _, _, err := net.SplitHostPort(c.Telemetry.Listen); err != nil {
			return fmt.Errorf("telemetry.listen must be host:port, got %q", c.Telemetry.Listen)
		}
	}
	// Queue defaults (§7.6): enabled by default, 256 KiB bound, drop-oldest,
	// rate-limited.
	q := &c.Queue
	if q.Enabled == nil {
		t := true
		q.Enabled = &t
	}
	if q.MaxBytes <= 0 {
		q.MaxBytes = 262144
	}
	if q.Drop == "" {
		q.Drop = "oldest"
	}
	if q.Drop != "oldest" && q.Drop != "newest" {
		return fmt.Errorf("queue.drop must be \"oldest\" or \"newest\", got %q", q.Drop)
	}
	return nil
}
