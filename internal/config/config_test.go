package config

import (
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/ColinFL/flexbraid/internal/crypto"
)

const sample = `
mode: client
listen: 0.0.0.0:51820
server: 203.0.113.1:4096
scheduler:
  mode: lb
  balance_by: capacity
fec:
  enabled: true
  mode: adaptive
  max_loss_pct: 20
  block_timeout_ms: 8
wans:
  - id: w1
    transport: faketcp
    iface: igc1
    capacity_mbps: 300
  - id: w2
    transport: udp
    iface: igc0
    capacity_mbps: 100
health:
  loss_alpha_fast: 0.4
  loss_alpha_slow: 0.03
  degrade_sec: 3
  recover_min: 2
crypto:
  key: test-secret
  cipher: chacha20poly1305
log:
  level: info
`

func TestLoadSample(t *testing.T) {
	c, err := loadString(sample)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if c.Mode != ModeClient {
		t.Errorf("mode = %q, want client", c.Mode)
	}
	if len(c.WANs) != 2 {
		t.Fatalf("expected 2 WANs, got %d", len(c.WANs))
	}
	if c.WANs[0].CapacityMbps != 300 || c.WANs[1].CapacityMbps != 100 {
		t.Errorf("capacities not parsed: %+v", c.WANs)
	}
	if c.WANs[0].Transport != TransportFakeTCP {
		t.Errorf("transport = %q, want faketcp", c.WANs[0].Transport)
	}
	if !c.FEC.Enabled || c.FEC.Mode != FECAdaptive {
		t.Errorf("fec = %+v", c.FEC)
	}
}

func TestFECCanBeDisabled(t *testing.T) {
	cfg := strings.Replace(sample, "enabled: true", "enabled: false", 1)
	c, err := loadString(cfg)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if c.FEC.Enabled {
		t.Error("FEC should be disabled")
	}
}

func TestFECOffModeDisables(t *testing.T) {
	cfg := strings.Replace(sample, "mode: adaptive", "mode: off", 1)
	c, err := loadString(cfg)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if c.FEC.Enabled {
		t.Error("fec.mode: off must imply disabled")
	}
}

func TestStandbyScheduler(t *testing.T) {
	cfg := strings.Replace(sample, "mode: lb", "mode: standby", 1)
	c, err := loadString(cfg)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if c.Scheduler.Mode != SchedulerStandby {
		t.Errorf("scheduler.mode = %q, want standby", c.Scheduler.Mode)
	}
}

func TestValidateRejectsNoWANs(t *testing.T) {
	cfg := strings.Replace(sample, "wans:\n  - id: w1\n    transport: faketcp\n    iface: igc1\n    capacity_mbps: 300\n  - id: w2\n    transport: udp\n    iface: igc0\n    capacity_mbps: 100\n", "wans: []\n", 1)
	if _, err := loadString(cfg); err == nil {
		t.Error("expected error for empty WAN list")
	}
}

func TestAffinityDefaultsToPacket(t *testing.T) {
	c, err := loadString(sample)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	// Packet is the default: the primary inner payload is a single
	// WireGuard flow, which flow-affinity would pin to one WAN.
	if c.Scheduler.Affinity != AffinityPacket {
		t.Errorf("affinity = %q, want packet", c.Scheduler.Affinity)
	}
	if c.MTU != 1420 {
		t.Errorf("mtu = %d, want 1420", c.MTU)
	}
}

func TestCrosspathRequiresPacketAffinity(t *testing.T) {
	// explicit flow affinity -> crosspath must be rejected
	cfg := strings.Replace(sample, "mode: lb\n  balance_by: capacity", "mode: lb\n  affinity: flow\n  balance_by: capacity", 1)
	cfg = strings.Replace(cfg, "mode: adaptive", "mode: crosspath", 1)
	if _, err := loadString(cfg); err == nil {
		t.Error("expected error: crosspath FEC with flow affinity")
	}
	// with packet affinity crosspath is accepted and gets the default
	// protection level of 0.5
	cfg = strings.Replace(sample, "mode: lb\n  balance_by: capacity", "mode: lb\n  affinity: packet\n  balance_by: capacity", 1)
	cfg = strings.Replace(cfg, "mode: adaptive", "mode: crosspath", 1)
	c, err := loadString(cfg)
	if err != nil {
		t.Fatalf("crosspath with packet affinity must be accepted: %v", err)
	}
	if c.FEC.ProtectionLevel != 0.5 {
		t.Fatalf("protection_level default must be 0.5, got %v", c.FEC.ProtectionLevel)
	}
	// out-of-range protection level must be rejected
	cfg = strings.Replace(sample, "mode: adaptive", "mode: crosspath\n  protection_level: 1.5", 1)
	if _, err := loadString(cfg); err == nil {
		t.Error("expected error: protection_level > 1")
	}
}

func TestKeyRequired(t *testing.T) {
	cfg := strings.Replace(sample, "key: test-secret", "key: \"\"", 1)
	if _, err := loadString(cfg); err == nil {
		t.Error("expected error: crypto.key is required")
	}
}

// TestNewFieldsParse: the M3.1 config surface (per-WAN binding, FEC
// geometry, delivery window, health debounce, capacity cap) parses.
func TestNewFieldsParse(t *testing.T) {
	cfg := `
mode: client
listen: 0.0.0.0:51820
server: 203.0.113.1:4096
scheduler:
  mode: lb
  affinity: packet
  capacity_cap_mbps: 500
fec:
  enabled: true
  mode: adaptive
  data_shards: 4
  max_loss_pct: 20
  block_timeout_ms: 15
wans:
  - id: w1
    transport: udp
    iface: igc1
    local_ip: 192.0.2.10
    capacity_mbps: 300
health:
  probe_interval: 2
  down_after_misses: 2
  down_grace_sec: 1.5
delivery:
  gap_timeout_ms: 150
  max_pending: 512
crypto:
  key: test-secret
`
	c, err := loadString(cfg)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if c.FEC.DataShards != 4 {
		t.Errorf("data_shards = %d, want 4", c.FEC.DataShards)
	}
	if c.FEC.BlockTimeoutMS != 15 {
		t.Errorf("block_timeout_ms = %d, want 15", c.FEC.BlockTimeoutMS)
	}
	if c.WANs[0].Iface != "igc1" || c.WANs[0].LocalIP != "192.0.2.10" {
		t.Errorf("wan binding not parsed: %+v", c.WANs[0])
	}
	if c.Health.ProbeInterval != 2 || c.Health.DownAfterMisses != 2 || c.Health.DownGraceSec != 1.5 {
		t.Errorf("health tuning not parsed: %+v", c.Health)
	}
	if c.Delivery.GapTimeoutMS != 150 || c.Delivery.MaxPending != 512 {
		t.Errorf("delivery not parsed: %+v", c.Delivery)
	}
	if c.Scheduler.CapacityCapMbps != 500 {
		t.Errorf("capacity_cap_mbps = %v, want 500", c.Scheduler.CapacityCapMbps)
	}
}

// TestProbeIntervalDefaultsToOne: probes default to 1s (fast failover for
// games), not the old 5s.
func TestProbeIntervalDefaultsToOne(t *testing.T) {
	c, err := loadString(sample)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if c.Health.ProbeInterval != 1 {
		t.Errorf("probe_interval default = %v, want 1", c.Health.ProbeInterval)
	}
	if c.Delivery.GapTimeoutMS != 100 {
		t.Errorf("gap_timeout_ms default = %d, want 100", c.Delivery.GapTimeoutMS)
	}
}

// TestRemovedKnobsAreRejected: the removed config surface (queue, crypto
// integrity_only) must fail loudly — Load uses KnownFields, so a config
// still carrying a removed knob cannot silently pass.
func TestRemovedKnobsAreRejected(t *testing.T) {
	cfg := strings.Replace(sample, "cipher: chacha20poly1305", "cipher: chacha20poly1305\n  integrity_only: true", 1)
	if _, err := loadString(cfg); err == nil {
		t.Error("integrity_only was removed; unknown keys must be rejected")
	}
	cfg = strings.Replace(sample, "balance_by: capacity", "balance_by: capacity\n  queue:\n    max_pkts: 64", 1)
	if _, err := loadString(cfg); err == nil {
		t.Error("scheduler.queue was removed; unknown keys must be rejected")
	}
}

func loadString(s string) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(strings.NewReader(s))
	dec.KnownFields(true)
	if err := dec.Decode(&c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// TestMaxLossPctDefaults: an enabled FEC block without max_loss_pct (or
// with an explicit 0) must default to DefaultMaxLossPct, not slip through
// validation only to crash the adaptive codec math at start (field-found:
// "invalid fec max_loss_pct 0 (must be 0 < x < 100)").
func TestMaxLossPctDefaults(t *testing.T) {
	omit := strings.Replace(sample, "  max_loss_pct: 20\n", "", 1)
	c, err := loadString(omit)
	if err != nil {
		t.Fatalf("adaptive FEC without max_loss_pct must load: %v", err)
	}
	if c.FEC.MaxLossPct != DefaultMaxLossPct {
		t.Errorf("default max_loss_pct = %v, want %v", c.FEC.MaxLossPct, DefaultMaxLossPct)
	}

	zero := strings.Replace(sample, "  max_loss_pct: 20\n", "  max_loss_pct: 0\n", 1)
	c, err = loadString(zero)
	if err != nil {
		t.Fatalf("adaptive FEC with max_loss_pct: 0 must load (defaulted): %v", err)
	}
	if c.FEC.MaxLossPct != DefaultMaxLossPct {
		t.Errorf("max_loss_pct 0 -> %v, want default %v", c.FEC.MaxLossPct, DefaultMaxLossPct)
	}

	// A disabled FEC must leave max_loss_pct untouched (no default needed):
	// baseline 0 + disabled -> stays 0.
	disabled := strings.Replace(sample, "  max_loss_pct: 20\n", "", 1)
	disabled = strings.Replace(disabled, "enabled: true", "enabled: false", 1)
	c, err = loadString(disabled)
	if err != nil {
		t.Fatalf("disabled FEC must load: %v", err)
	}
	if c.FEC.MaxLossPct != 0 {
		t.Errorf("disabled FEC max_loss_pct = %v, want 0 (untouched)", c.FEC.MaxLossPct)
	}
}

// TestDeliveryMaxPendingMatchesReplayWindow pins the DESIGN §5 invariant:
// the reorder-buffer bound must never exceed the anti-replay window, or a
// multi-path link drops legitimate reordered frames as replays.
func TestDeliveryMaxPendingMatchesReplayWindow(t *testing.T) {
	if DeliveryMaxPending != crypto.DefaultReplayWindow {
		t.Fatalf("DeliveryMaxPending (%d) != crypto.DefaultReplayWindow (%d) — "+
			"the delivery buffer must be <= the anti-replay window (DESIGN §5)",
			DeliveryMaxPending, crypto.DefaultReplayWindow)
	}
}

func TestDeliveryMaxPendingRejectsOverReplayWindow(t *testing.T) {
	delivery := func(maxPending int) string {
		return strings.Replace(sample, "health:\n",
			fmt.Sprintf("delivery:\n  max_pending: %d\nhealth:\n", maxPending), 1)
	}
	// At the bound it must load.
	if _, err := loadString(delivery(DeliveryMaxPending)); err != nil {
		t.Fatalf("max_pending == DeliveryMaxPending must load: %v", err)
	}
	// Just past it -> hard error (would silently drop reordered frames).
	if _, err := loadString(delivery(DeliveryMaxPending + 1)); err == nil {
		t.Error("max_pending above the anti-replay window must be rejected")
	}
}
