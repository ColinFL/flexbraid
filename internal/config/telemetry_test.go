package config

// Telemetry config tests (M5.1).

import (
	"strings"
	"testing"
)

func TestTelemetryDefaults(t *testing.T) {
	c, err := loadString(sample)
	if err != nil {
		t.Fatal(err)
	}
	if c.Telemetry.Path != "/stats" {
		t.Errorf("Path default = %q, want /stats", c.Telemetry.Path)
	}
	if c.Telemetry.IntervalSec != 0 || c.Telemetry.Listen != "" {
		t.Errorf("telemetry should default off, got %+v", c.Telemetry)
	}
}

func TestTelemetryValidation(t *testing.T) {
	// interval must be >= 0
	cfg := sample + "telemetry:\n  interval_sec: -1\n"
	if _, err := loadString(cfg); err == nil || !strings.Contains(err.Error(), "interval_sec") {
		t.Fatalf("want interval_sec error, got %v", err)
	}
	// listen must be host:port
	cfg = sample + "telemetry:\n  listen: \"127.0.0.1\"\n"
	if _, err := loadString(cfg); err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("want listen error, got %v", err)
	}
}

func TestTelemetryPathCustom(t *testing.T) {
	cfg := sample + "telemetry:\n  listen: \"127.0.0.1:9080\"\n  path: /metrics\n  interval_sec: 5\n"
	c, err := loadString(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.Telemetry.Path != "/metrics" || c.Telemetry.IntervalSec != 5 {
		t.Errorf("got %+v", c.Telemetry)
	}
}

func TestQueueDefaults(t *testing.T) {
	c, err := loadString(sample)
	if err != nil {
		t.Fatal(err)
	}
	if c.Queue.Enabled == nil || !*c.Queue.Enabled {
		t.Error("queue.enabled should default true")
	}
	if c.Queue.MaxBytes != 262144 {
		t.Errorf("queue.max_bytes default = %d, want 262144", c.Queue.MaxBytes)
	}
	if c.Queue.Drop != "oldest" {
		t.Errorf("queue.drop default = %q, want oldest", c.Queue.Drop)
	}
}

func TestQueueValidation(t *testing.T) {
	cfg := sample + "queue:\n  enabled: false\n  drop: bogus\n"
	if _, err := loadString(cfg); err == nil {
		t.Fatal("queue.drop=bogus should be rejected")
	}
	cfg = sample + "queue:\n  enabled: false\n  max_bytes: 4096\n"
	c, err := loadString(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if *c.Queue.Enabled {
		t.Error("queue.enabled should be false")
	}
	if c.Queue.MaxBytes != 4096 {
		t.Errorf("max_bytes = %d, want 4096", c.Queue.MaxBytes)
	}
}
