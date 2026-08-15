package tunnel

import (
	"testing"
	"time"

	"github.com/ColinFL/flexbraid/internal/frame"
)

// TestDeliverySkipsGapAfterTimeout: a missing seq stalls delivery for at
// most gapTimeout, then the hole is skipped.
func TestDeliverySkipsGapAfterTimeout(t *testing.T) {
	d := newDeliveryBuffer(50*time.Millisecond, 64)
	now := time.Now()

	// Frames 5..8 arrive before frame 1: they must wait in the buffer.
	var out []*frame.Frame
	for _, seq := range []uint32{5, 6, 7, 8} {
		out = append(out, d.Push([]*frame.Frame{{Seq: seq}})...)
	}
	if len(out) != 0 {
		t.Fatalf("frames must wait for the gap, delivered %d", len(out))
	}
	// Before the timeout: still blocked.
	if out := d.Tick(now.Add(30 * time.Millisecond)); len(out) != 0 {
		t.Fatalf("gap skipped too early: %d frames", len(out))
	}
	// After the timeout: hole skipped, queued frames delivered in order.
	out = d.Tick(now.Add(100 * time.Millisecond))
	if len(out) != 4 {
		t.Fatalf("want 4 delivered after gap timeout, got %d", len(out))
	}
	for i, f := range out {
		if f.Seq != uint32(5+i) {
			t.Fatalf("delivery order broken at %d: seq %d", i, f.Seq)
		}
	}
}

// TestDeliveryMaxPendingDropsOldest: a stalled path cannot grow the buffer
// without bound — beyond maxPending the longest-waiting frame is dropped.
func TestDeliveryMaxPendingDropsOldest(t *testing.T) {
	d := newDeliveryBuffer(50*time.Millisecond, 4)
	now := time.Now()

	// Fill the buffer with a gap at seq 1: frames 5,6,7,8 pending.
	for _, seq := range []uint32{5, 6, 7, 8} {
		d.Push([]*frame.Frame{{Seq: seq}})
	}
	// One more frame beyond the cap: the oldest pending (5) must go.
	d.Push([]*frame.Frame{{Seq: 9}})

	out := d.Tick(now.Add(100 * time.Millisecond))
	if len(out) != 4 {
		t.Fatalf("want 4 frames after cap eviction, got %d", len(out))
	}
	if out[0].Seq != 6 || out[3].Seq != 9 {
		t.Fatalf("expected eviction of the oldest (5), got seqs %d..%d", out[0].Seq, out[3].Seq)
	}
}

// TestDeliveryInOrderPassesThrough: contiguous frames never wait.
func TestDeliveryInOrderPassesThrough(t *testing.T) {
	d := newDeliveryBuffer(50*time.Millisecond, 64)
	for seq := uint32(1); seq <= 3; seq++ {
		out := d.Push([]*frame.Frame{{Seq: seq}})
		if len(out) != 1 || out[0].Seq != seq {
			t.Fatalf("contiguous frame %d not delivered immediately", seq)
		}
	}
}

// TestDeliveryIgnoresLateDuplicates: frames already delivered (or older
// than the delivered prefix) are dropped.
func TestDeliveryIgnoresLateDuplicates(t *testing.T) {
	d := newDeliveryBuffer(50*time.Millisecond, 64)
	d.Push([]*frame.Frame{{Seq: 1}})
	if out := d.Push([]*frame.Frame{{Seq: 1}}); len(out) != 0 {
		t.Fatalf("duplicate seq must be dropped")
	}
	if out := d.Push([]*frame.Frame{{Seq: 0}}); len(out) != 0 {
		t.Fatalf("old seq must be dropped")
	}
}
