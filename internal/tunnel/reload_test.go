package tunnel

// Runtime-reload tests (M5.2): live knobs must take effect on the running
// client, structural changes must be rejected without mutating anything.

import (
	"errors"
	"testing"
	"time"

	"github.com/ColinFL/flexbraid/internal/config"
)

func TestClientReloadLiveKnobs(t *testing.T) {
	_, cli, fakeWG, wgClient := startTestPair(t, "psk")
	_ = fakeWG
	_ = wgClient

	nc := copyClientCfg(cli.cfg)
	nc.Delivery.GapTimeoutMS = 42
	nc.Delivery.MaxPending = 2048
	nc.WANs[0].CapacityMbps = 250
	nc.Health.LossAlphaFast = 0.7

	if err := cli.Reload(nc); err != nil {
		t.Fatalf("reload: %v", err)
	}

	if cli.delivery.gapTimeout != 42*time.Millisecond {
		t.Errorf("gapTimeout = %v, want 42ms", cli.delivery.gapTimeout)
	}
	if cli.delivery.maxPending != 2048 {
		t.Errorf("maxPending = %d, want 2048", cli.delivery.maxPending)
	}
	paths := cli.sched.Paths()
	if len(paths) != 1 || paths[0].CapacityMbps != 250 {
		t.Errorf("scheduler capacity = %+v, want 250", paths)
	}
}

func TestClientReloadRejectsStructural(t *testing.T) {
	_, cli, _, _ := startTestPair(t, "psk")

	// server address change => restart required, nothing applied.
	c := cli.cfg
	copy := *c
	copy.Server = "203.0.113.9:4096"
	if err := cli.Reload(&copy); !errors.Is(err, ErrReloadRequiresRestart) {
		t.Fatalf("want ErrReloadRequiresRestart, got %v", err)
	}

	// crypto key change => restart required.
	c2 := *c
	c2.Crypto.Key = "another-key"
	if err := cli.Reload(&c2); !errors.Is(err, ErrReloadRequiresRestart) {
		t.Fatalf("want ErrReloadRequiresRestart for key, got %v", err)
	}
}

// copyClientCfg makes a shallow-but-safe copy of a client config so tests
// can mutate reloadable fields without aliasing the live config.
func copyClientCfg(base *config.Config) *config.Config {
	c := *base
	c.WANs = append([]config.WAN(nil), base.WANs...)
	return &c
}
