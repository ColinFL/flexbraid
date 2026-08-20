package tunnel

// sendQueue tests (M5.3, §7.6): FIFO order, bounded memory with the two
// drop policies, token-bucket pacing, and ctx-cancelled shutdown.

import (
	"context"
	"sync"
	"testing"
	"time"
)

func collectAll(t *testing.T, q *sendQueue, want int) [][]byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	got := make([][]byte, 0, want)
	for len(got) < want {
		b, ok := q.popNext(ctx)
		if !ok {
			t.Fatalf("popNext returned !ok after %d frames", len(got))
		}
		got = append(got, b)
	}
	return got
}

func TestSendQueueFIFO(t *testing.T) {
	q := newSendQueue(1024, dropOldest, 0)
	frames := [][]byte{{1}, {2}, {3}, {4}}
	for _, f := range frames {
		if !q.enqueue(f) {
			t.Fatalf("enqueue %v rejected", f)
		}
	}
	got := collectAll(t, q, len(frames))
	for i, g := range got {
		if len(g) != 1 || g[0] != frames[i][0] {
			t.Fatalf("frame %d = %v, want %v (FIFO)", i, g, frames[i])
		}
	}
}

func TestSendQueueDropOldest(t *testing.T) {
	// Queue holds ~3 units (maxBytes 8, frames of 3 bytes each → 2 fit, 1 new replaces oldest).
	q := newSendQueue(6, dropOldest, 0)
	for _, b := range [][]byte{{1, 1, 1}, {2, 2, 2}, {3, 3, 3}} {
		q.enqueue(b)
	}
	// Dropped: frame1 evicted to make room for frame3 (oldest policy).
	got := collectAll(t, q, 2)
	if got[0][0] != 2 || got[1][0] != 3 {
		t.Fatalf("drop-oldest: got %v, want [2 3]", got)
	}
	f, b, _ := q.stats()
	if f != 2 || b != 6 {
		t.Fatalf("stats frames=%d bytes=%d, want 2/6", f, b)
	}
}

func TestSendQueueDropNewest(t *testing.T) {
	q := newSendQueue(6, dropNewest, 0)
	for _, b := range [][]byte{{1, 1, 1}, {2, 2, 2}, {3, 3, 3}} {
		q.enqueue(b)
	}
	// Newest (frame3) rejected; frames 1,2 remain.
	got := collectAll(t, q, 2)
	if got[0][0] != 1 || got[1][0] != 2 {
		t.Fatalf("drop-newest: got %v, want [1 2]", got)
	}
}

func TestSendQueueRateLimit(t *testing.T) {
	// 500 bytes/sec; push 5 frames @ 100 B = 500 B → should take ~0.8s.
	q := newSendQueue(10000, dropOldest, 500)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	frame := make([]byte, 100)
	for i := 0; i < 5; i++ {
		q.enqueue(frame)
	}
	var mu sync.Mutex
	var sent int
	start := time.Now()
	done := make(chan struct{})
	go func() {
		defer close(done)
		q.run(ctx, func(b []byte) error {
			mu.Lock()
			sent++
			mu.Unlock()
			return nil
		}, nil)
	}()
	<-done
	elapsed := time.Since(start)
	mu.Lock()
	totalSent := sent
	mu.Unlock()
	if totalSent != 5 {
		t.Fatalf("sent %d frames, want 5", totalSent)
	}
	if elapsed < 700*time.Millisecond {
		t.Fatalf("rate limiter too fast: %v for 5×100B @500B/s", elapsed)
	}
}

func TestSendQueueShutdownOnCancel(t *testing.T) {
	q := newSendQueue(1024, dropOldest, 0)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, ok := q.popNext(ctx) // blocks until cancel
	if ok {
		t.Fatal("popNext after cancel returned ok=true")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("popNext did not unblock promptly after ctx cancel")
	}
}

func TestSendQueueClosed(t *testing.T) {
	q := newSendQueue(1024, dropOldest, 0)
	q.close()
	if q.enqueue([]byte{1}) {
		t.Fatal("enqueue after close accepted a frame")
	}
	if _, ok := q.popNext(context.Background()); ok {
		t.Fatal("popNext on closed empty queue returned ok=true")
	}
}

func TestParseQueueDrop(t *testing.T) {
	if _, err := parseQueueDrop("bogus"); err == nil {
		t.Fatal("parseQueueDrop(bogus) should error")
	}
	if _, err := parseQueueDrop("newest"); err != nil {
		t.Fatal(err)
	}
}
