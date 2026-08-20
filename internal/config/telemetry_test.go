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
