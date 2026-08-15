// Delivery buffer: in-order reassembly of the server → client stream.
//
// With packet-level scheduling the server sends FEC blocks to different
// WANs, so frames arrive at the client interleaved. The delivery buffer
// restores global seq order before handing datagrams to the inner WireGuard
// peer (design §7.2, "delivery buffer = reorder + jitter in one window").
//
// Gap policy: a missing seq blocks delivery until gapTimeout elapses, then
// the hole is skipped (deliver what arrived, advance past the gap). This
// bounds head-of-line blocking when a block is lost beyond FEC repair —
// WireGuard and inner TCP tolerate the resulting reorder/loss far better
// than a stalled stream.
package tunnel

import (
	"sync"
	"time"

	"github.com/ColinFL/flexbraid/internal/frame"
)

// deliveryBuffer reorders frames by their global seq.
type deliveryBuffer struct {
	mu         sync.Mutex
	next       uint32 // next expected seq
	pending    map[uint32]*frame.Frame
	gapSince   time.Time // when next became missing (zero = no gap)
	gapTimeout time.Duration
	maxPending int // BDP guard: drop-oldest bound on pending
}

func newDeliveryBuffer(gapTimeout time.Duration, maxPending int) *deliveryBuffer {
	if gapTimeout <= 0 {
		gapTimeout = 100 * time.Millisecond
	}
	if maxPending <= 0 {
		maxPending = 4096
	}
	return &deliveryBuffer{
		next:       1, // seqs start at 1 (session.NextSeq)
		pending:    make(map[uint32]*frame.Frame),
		gapTimeout: gapTimeout,
		maxPending: maxPending,
	}
}

// Push accepts decoded frames (any order) and returns those that can be
// delivered in order now.
func (d *deliveryBuffer) Push(frames []*frame.Frame) []*frame.Frame {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []*frame.Frame
	for _, f := range frames {
		// int32 cast handles uint32 wraparound (seq space is 2^32).
		if int32(f.Seq-d.next) < 0 {
			continue // already delivered (late duplicate)
		}
		if f.Seq == d.next {
			out = append(out, f)
			d.next++
			d.drainContiguous(&out)
		} else {
			if _, dup := d.pending[f.Seq]; !dup {
				// BDP guard: a stalled path must not grow the buffer
				// without bound. Drop the longest-waiting frame (the
				// lowest seq) — it is furthest past its usefulness.
				if len(d.pending) >= d.maxPending {
					lo := f.Seq
					for seq := range d.pending {
						if int32(seq-lo) < 0 {
							lo = seq
						}
					}
					delete(d.pending, lo)
				}
				d.pending[f.Seq] = f
			}
			if d.gapSince.IsZero() {
				d.gapSince = time.Now()
			}
		}
	}
	return out
}

// Tick skips a stale gap: called periodically; if next has been missing
// for gapTimeout, deliver the pending frames and advance past the hole.
func (d *deliveryBuffer) Tick(now time.Time) []*frame.Frame {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.gapSince.IsZero() || now.Sub(d.gapSince) < d.gapTimeout {
		return nil
	}
	// Advance next to the lowest pending seq (skip the hole), then drain.
	lo := uint32(0)
	for seq := range d.pending {
		if lo == 0 || int32(seq-lo) < 0 {
			lo = seq
		}
	}
	if lo == 0 {
		// Nothing pending: just skip the hole itself.
		d.next++
		d.gapSince = time.Time{}
		return nil
	}
	d.next = lo
	var out []*frame.Frame
	d.drainContiguous(&out)
	return out
}

// drainContiguous delivers the run of pending frames starting at next.
func (d *deliveryBuffer) drainContiguous(out *[]*frame.Frame) {
	for {
		f, ok := d.pending[d.next]
		if !ok {
			break
		}
		delete(d.pending, d.next)
		*out = append(*out, f)
		d.next++
	}
	if len(d.pending) == 0 {
		d.gapSince = time.Time{}
	}
}
