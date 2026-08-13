package config

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
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

func TestAffinityDefaultsToFlow(t *testing.T) {
	c, err := loadString(sample)
	if err != nil {
		t.Fatalf("load failed: %v", err)
	}
	if c.Scheduler.Affinity != AffinityFlow {
		t.Errorf("affinity = %q, want flow", c.Scheduler.Affinity)
	}
	if c.MTU != 1420 {
		t.Errorf("mtu = %d, want 1420", c.MTU)
	}
}

func TestCrosspathRequiresPacketAffinity(t *testing.T) {
	// default affinity is flow -> crosspath must be rejected
	cfg := strings.Replace(sample, "mode: adaptive", "mode: crosspath", 1)
	if _, err := loadString(cfg); err == nil {
		t.Error("expected error: crosspath FEC with flow affinity")
	}
	// with packet affinity it must be accepted
	cfg = strings.Replace(sample, "mode: lb\n  balance_by: capacity", "mode: lb\n  affinity: packet\n  balance_by: capacity", 1)
	cfg = strings.Replace(cfg, "mode: adaptive", "mode: crosspath", 1)
	c, err := loadString(cfg)
	if err != nil {
		t.Fatalf("crosspath with packet affinity should be valid: %v", err)
	}
	if c.FEC.Mode != FECCrosspath || c.Scheduler.Affinity != AffinityPacket {
		t.Errorf("unexpected config: fec=%s affinity=%s", c.FEC.Mode, c.Scheduler.Affinity)
	}
}

func TestKeyRequired(t *testing.T) {
	cfg := strings.Replace(sample, "key: test-secret", "key: \"\"", 1)
	if _, err := loadString(cfg); err == nil {
		t.Error("expected error: crypto.key is required")
	}
}

func loadString(s string) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal([]byte(s), &c); err != nil {
		return nil, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}
