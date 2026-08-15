package scheduler

import (
	"testing"

	"github.com/ColinFL/flexbraid/internal/frame"
	"github.com/ColinFL/flexbraid/internal/health"
)

func mkFrame(seq uint32) *frame.Frame { return &frame.Frame{Seq: seq} }

// TestLBWeightedByCapacity: with 300/100 Mbps, the 300 path must carry ~3x.
func TestLBWeightedByCapacity(t *testing.T) {
	s := New(Options{Mode: ModeLB, Affinity: AffPacket, BalanceBy: ByCapacity})
	s.AddPath("w1", 300)
	s.AddPath("w2", 100)

	const n = 20000
	counts := map[string]int{}
	for i := 0; i < n; i++ {
		id, ok := s.Pick(mkFrame(uint32(i)))
		if !ok {
			t.Fatal("pick failed with two healthy paths")
		}
		counts[id]++
	}
	w1, w2 := counts["w1"], counts["w2"]
	ratio := float64(w1) / float64(w2)
	if ratio < 2.4 || ratio > 3.6 {
		t.Fatalf("w1/w2 ratio %.2f out of expected ~3.0 (w1=%d w2=%d)", ratio, w1, w2)
	}
}

// TestDownPathExcluded: a DOWN path gets no traffic at all.
func TestDownPathExcluded(t *testing.T) {
	s := New(Options{Mode: ModeLB, Affinity: AffPacket})
	s.AddPath("w1", 100)
	s.AddPath("w2", 100)
	s.OnState("w2", health.StateDown, 1.0)

	for i := 0; i < 1000; i++ {
		id, ok := s.Pick(mkFrame(uint32(i)))
		if !ok {
			t.Fatal("pick failed with one healthy path")
		}
		if id == "w2" {
			t.Fatal("down path received traffic")
		}
	}
	if s.Healthy() == false {
		t.Fatal("scheduler must be healthy with w1 up")
	}
}

// TestDegradedDrains: a DEGRADED path still gets a token share (in-flight
// blocks drain) but far less than healthy ones.
func TestDegradedDrains(t *testing.T) {
	s := New(Options{Mode: ModeLB, Affinity: AffPacket})
	s.AddPath("w1", 100)
	s.AddPath("w2", 100)
	s.OnState("w2", health.StateDegraded, 0.5)

	const n = 20000
	counts := map[string]int{}
	for i := 0; i < n; i++ {
		id, _ := s.Pick(mkFrame(uint32(i)))
		counts[id]++
	}
	if counts["w2"] > n/5 {
		t.Fatalf("degraded path got too much traffic: w2=%d/%d", counts["w2"], n)
	}
	if counts["w2"] == 0 {
		t.Fatal("degraded path got nothing — drain broken (should carry a token share)")
	}
}

// TestAllDownFails: with everything down, Pick reports failure.
func TestAllDownFails(t *testing.T) {
	s := New(Options{Mode: ModeLB})
	s.AddPath("w1", 100)
	s.OnState("w1", health.StateDown, 1.0)
	if _, ok := s.Pick(mkFrame(1)); ok {
		t.Fatal("pick must fail when all paths are down")
	}
	if s.Healthy() {
		t.Fatal("Healthy must be false when all paths are down")
	}
}

// TestStandbyFailover: standby mode keeps traffic on the first path and
// switches to the second only when the first goes down.
func TestStandbyFailover(t *testing.T) {
	s := New(Options{Mode: ModeStandby})
	s.AddPath("primary", 100)
	s.AddPath("backup", 50)

	for i := 0; i < 100; i++ {
		id, _ := s.Pick(mkFrame(uint32(i)))
		if id != "primary" {
			t.Fatalf("standby must use primary while healthy, got %s", id)
		}
	}
	s.OnState("primary", health.StateDown, 1.0)
	for i := 0; i < 100; i++ {
		id, _ := s.Pick(mkFrame(uint32(i)))
		if id != "backup" {
			t.Fatalf("standby must fail over to backup, got %s", id)
		}
	}
	// Recovery returns to primary.
	s.OnState("primary", health.StateHealthy, 0)
	for i := 0; i < 100; i++ {
		id, _ := s.Pick(mkFrame(uint32(i)))
		if id != "primary" {
			t.Fatalf("standby must return to primary after recovery, got %s", id)
		}
	}
}

// TestStandbySkipsDegraded: the standby must abandon a DEGRADED primary
// immediately (loss beyond FEC capacity) — not wait for a hard failure.
// Hierarchy: HEALTHY > DEGRADED > DOWN.
func TestStandbySkipsDegraded(t *testing.T) {
	s := New(Options{Mode: ModeStandby})
	s.AddPath("primary", 100)
	s.AddPath("backup", 50)

	// Primary degrades: all traffic moves to the healthy backup.
	s.OnState("primary", health.StateDegraded, 0.5)
	for i := 0; i < 100; i++ {
		id, _ := s.Pick(mkFrame(uint32(i)))
		if id != "backup" {
			t.Fatalf("standby must switch to backup while primary is DEGRADED, got %s", id)
		}
	}
	// Backup degrades too: drain on the least-bad (config order = primary).
	s.OnState("backup", health.StateDegraded, 0.6)
	for i := 0; i < 100; i++ {
		id, _ := s.Pick(mkFrame(uint32(i)))
		if id != "primary" {
			t.Fatalf("all-degraded standby must drain on config order (primary), got %s", id)
		}
	}
	// Backup recovers: it becomes the sole healthy path and takes over.
	s.OnState("backup", health.StateHealthy, 0)
	for i := 0; i < 100; i++ {
		id, _ := s.Pick(mkFrame(uint32(i)))
		if id != "backup" {
			t.Fatalf("healthy backup must carry traffic, got %s", id)
		}
	}
	// Primary recovers: config order wins again.
	s.OnState("primary", health.StateHealthy, 0)
	for i := 0; i < 100; i++ {
		id, _ := s.Pick(mkFrame(uint32(i)))
		if id != "primary" {
			t.Fatalf("standby must return to primary after recovery, got %s", id)
		}
	}
}

// TestFlowAffinityStable: with flow affinity, the same inner 4-tuple always
// lands on the same WAN while the set is stable, and removing a path only
// migrates its flows.
func TestFlowAffinityStable(t *testing.T) {
	s := New(Options{Mode: ModeLB, Affinity: AffFlow})
	s.AddPath("w1", 100)
	s.AddPath("w2", 100)

	// A fake inner IPv4/UDP packet.
	pkt := func(src, dst, sport, dport uint16) []byte {
		b := make([]byte, 28)
		b[0] = 0x45 // IPv4, IHL 5
		b[9] = 17   // UDP
		b[12] = byte(src >> 8)
		b[13] = byte(src)
		b[14] = byte(src >> 8)
		b[15] = byte(src)
		b[16] = byte(dst >> 8)
		b[17] = byte(dst)
		b[18] = byte(dst >> 8)
		b[19] = byte(dst)
		b[20] = byte(sport >> 8)
		b[21] = byte(sport)
		b[22] = byte(dport >> 8)
		b[23] = byte(dport)
		return b
	}
	f1 := &frame.Frame{Seq: 1, Payload: pkt(1000, 2000, 1111, 2222)}
	f2 := &frame.Frame{Seq: 2, Payload: pkt(1000, 2000, 1111, 2222)} // same flow

	first, ok := s.Pick(f1)
	if !ok {
		t.Fatal("pick failed")
	}
	for i := 0; i < 50; i++ {
		id, _ := s.Pick(f2)
		if id != first {
			t.Fatalf("flow migrated across picks: %s then %s", first, id)
		}
	}
	// Kill w2: the flow may migrate to w1 but must never pick a dead path.
	s.OnState("w2", health.StateDown, 1.0)
	if id, ok := s.Pick(f2); !ok || id != "w1" {
		t.Fatalf("after w2 down, flow must land on w1, got %s ok=%v", id, ok)
	}
}
