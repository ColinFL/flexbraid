package tunnel

// Telemetry tests (M5.1): Snapshot must be non-empty, well-shaped and safe
// to marshal — the exact contract the HTTP endpoint and periodic log rely on.

import (
	"encoding/json"
	"testing"
	"time"
)

// TestClientSnapshotShape starts a real pair, pushes a frame through, and
// asserts the client snapshot exposes the live WAN and delivery state.
func TestClientSnapshotShape(t *testing.T) {
	srv, cli, fakeWG, wgClient := startTestPair(t, "psk")
	_ = srv // startTestPair registers its own cleanup

	// Push real traffic so the WAN sees a frame (framesSent > 0).
	sendUntilReceived(t, wgClient, mustUDPAddr(t, cli.ingress.LocalAddr().String()), fakeWG,
		[]byte("telemetry-check"), 5*time.Second)

	snap := cli.Snapshot()
	if snap.Mode != "client" {
		t.Fatalf("mode = %q, want client", snap.Mode)
	}
	if len(snap.WANs) == 0 {
		t.Fatal("snapshot has no WAN entries")
	}
	if snap.UptimeSec <= 0 {
		t.Fatalf("uptime = %v, want > 0", snap.UptimeSec)
	}
	w := snap.WANs[0]
	if w.ID == "" {
		t.Error("WAN id empty")
	}
	if w.State == "" {
		t.Error("WAN state empty")
	}
	if w.FramesSent == 0 {
		t.Error("frames_sent = 0 after traffic")
	}
	// JSON contract: every field serializes.
	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("json.Marshal(snapshot): %v", err)
	}
	if len(data) < 100 {
		t.Fatalf("snapshot JSON suspiciously small: %d bytes", len(data))
	}
}

// TestSnapshotJSONFields pins the wire names so dashboards don't silently
// break when the struct layout changes.
func TestSnapshotJSONFields(t *testing.T) {
	data, err := json.Marshal(Snapshot{
		Mode: "client", WANs: []WANStats{{ID: "w1"}},
		FEC:      FECStats{DataShards: 4},
		Delivery: DeliveryStats{MaxPending: 4096},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"mode"`, `"uptime_sec"`, `"wans"`, `"fec"`, `"delivery"`,
		`"id"`, `"state"`, `"loss_pct"`, `"rtt_ms"`, `"jitter_ms"`, `"frames_sent"`,
		`"blocks_sent"`, `"frames_lost"`, `"recovered"`, `"pending"`, `"drops"`,
	} {
		if !jsonContains(string(data), want) {
			t.Errorf("snapshot JSON missing field %s\n%s", want, data)
		}
	}
}

func jsonContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
