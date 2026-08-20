package tunnel

// Bounded per-WAN send queue + token-bucket rate limiter (docs/DESIGN.md
// §7.6). WireGuard has no congestion control, so FlexBraid owns the queue
// discipline on the client side (the office box has multiple WANs to pace):
//
//   - a bounded FIFO holds sealed frames; when full, the configured drop
//     policy applies ("oldest" — evict the longest-buffered frame so TCP-ish
//     flows keep the newest bytes; "newest" — drop the just-arrived frame so
//     real-time UDP always gets the latest state),
//   - a token bucket gates the consumer goroutine to the WAN's declared
//     capacity, so a fast WAN cannot bufferbloat a slow one.
//
// Producers are non-blocking (enqueue-only) for bounded memory; the
// consumer goroutine owns the actual transport write.

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"
)

// queueDrop is the overflow policy.
type queueDrop int

const (
	dropOldest queueDrop = iota
	dropNewest
)

func parseQueueDrop(s string) (queueDrop, error) {
	switch s {
	case "oldest":
		return dropOldest, nil
	case "newest":
		return dropNewest, nil
	default:
		return 0, fmt.Errorf("queue.drop: %q", s)
	}
}

// sendQueue is concurrency-safe: any number of producers may enqueue while
// one consumer drains.
type sendQueue struct {
	mu       sync.Mutex
	wake     chan struct{}
	closed   bool
	maxBytes int
	drop     queueDrop
	q        [][]byte
	bytes    int

	// token bucket (rate limiter); rate <= 0 disables pacing.
	rate    float64 // bytes/sec
	burst   float64 // bucket capacity in bytes
	tokens  float64
	lastRef time.Time

	framesSent uint64
	bytesSent  uint64
	dropped    uint64 // frames dropped on overflow (telemetry)
}

func newSendQueue(maxBytes int, drop queueDrop, rateBps float64) *sendQueue {
	if maxBytes <= 0 {
		maxBytes = 262144
	}
	return &sendQueue{
		maxBytes: maxBytes,
		drop:     drop,
		rate:     rateBps,
		burst:    float64(maxBytes),
		tokens:   float64(maxBytes),
		lastRef:  time.Now(),
		wake:     make(chan struct{}, 1),
	}
}

// enqueue accepts one sealed frame, applying the drop policy on overflow.
// It never blocks. Returns true if accepted.
func (q *sendQueue) enqueue(b []byte) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.closed {
		return false
	}
	if len(b) > q.maxBytes {
		q.dropped++
		return false
	}
	if q.bytes+len(b) > q.maxBytes {
		switch q.drop {
		case dropNewest:
			q.dropped++
			return false
		default:
			// Evict the oldest until the new frame fits.
			for q.bytes+len(b) > q.maxBytes {
				if len(q.q) == 0 {
					q.dropped++
					return false
				}
				head := q.q[0]
				q.q = q.q[1:]
				q.bytes -= len(head)
				q.dropped++
			}
		}
	}
	q.q = append(q.q, b)
	q.bytes += len(b)
	q.signal()
	return true
}

// signal wakes a blocked consumer without blocking the producer.
func (q *sendQueue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// popNext returns the next frame, blocking until one is available, the
// queue is closed, or ctx is done. ok=false means closed/cancelled.
func (q *sendQueue) popNext(ctx context.Context) ([]byte, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for {
		if len(q.q) > 0 {
			b := q.q[0]
			q.q = q.q[1:]
			q.bytes -= len(b)
			q.framesSent++
			q.bytesSent += uint64(len(b))
			return b, true
		}
		if q.closed {
			return nil, false
		}
		q.mu.Unlock()
		select {
		case <-ctx.Done():
			q.mu.Lock()
			return nil, false
		case <-q.wake:
		}
		q.mu.Lock()
	}
}

// takeTokens blocks until len(b) bytes are available from the bucket.
// Returns false on ctx cancellation. A zero/negative rate never blocks.
func (q *sendQueue) takeTokens(ctx context.Context, n int) bool {
	if q.rate <= 0 {
		return ctx.Err() == nil
	}
	need := float64(n)
	timeout := time.NewTimer(0)
	defer timeout.Stop()
	for {
		q.mu.Lock()
		now := time.Now()
		elapsed := now.Sub(q.lastRef).Seconds()
		q.lastRef = now
		q.tokens = math.Min(q.burst, q.tokens+elapsed*q.rate)
		if q.tokens >= need {
			q.tokens -= need
			q.mu.Unlock()
			return ctx.Err() == nil
		}
		deficit := (need - q.tokens) / q.rate
		q.mu.Unlock()
		timeout.Reset(time.Duration(deficit * float64(time.Second)))
		select {
		case <-ctx.Done():
			return false
		case <-timeout.C:
		}
	}
}

// run is the consumer: drain the FIFO, rate-gating before each write.
func (q *sendQueue) run(ctx context.Context, send func([]byte) error, log *slog.Logger) {
	for {
		b, ok := q.popNext(ctx)
		if !ok {
			return
		}
		if !q.takeTokens(ctx, len(b)) {
			return
		}
		if err := send(b); err != nil && log != nil {
			log.Warn("queue send failed", "error", err)
		}
	}
}

func (q *sendQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.signal()
}

func (q *sendQueue) stats() (frames, bytes, dropped uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.framesSent, q.bytesSent, q.dropped
}
