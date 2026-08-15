package health

import (
	"testing"
	"time"
)

func fastOpts() Options {
	return Options{
		MaxLoss:         0.2,
		DegradeAfter:    400 * time.Millisecond,
		RecoverAfter:    500 * time.Millisecond,
		DownAfterMisses: 3,
		LossAlphaFast:   0.5,
		LossAlphaSlow:   0.1,
		JitterAlpha:     0.1,
	}
}

// TestHealthyStaysHealthy: a clean path never leaves HEALTHY.
func TestHealthyStaysHealthy(t *testing.T) {
	m := New(fastOpts())
	now := time.Now()
	for i := 0; i < 100; i++ {
		m.ObserveSample(0, 10*time.Millisecond)
		m.Tick(now.Add(time.Duration(i) * 100 * time.Millisecond))
	}
	if m.State() != StateHealthy {
		t.Fatalf("clean path left HEALTHY: %v", m.State())
	}
}

// TestLossSpikeDegradesThenEscalates: sustained loss above FEC capacity
// moves HEALTHY → DEGRADED (after DegradeAfter) → DOWN (escalation).
func TestLossSpikeDegradesThenEscalates(t *testing.T) {
	m := New(fastOpts())
	now := time.Now()
	// Spike: every probe is lost. The fast-rise EWMA (α=0.5) exceeds 0.2
	// after two samples.
	for i := 0; i < 2; i++ {
		m.ObserveSample(1, 0)
	}
	if got := m.Loss(); got <= m.maxLoss {
		t.Fatalf("loss estimate %v did not rise above maxLoss after spike", got)
	}
	// Still healthy until the condition is sustained: condSince starts on
	// the first tick, DegradeAfter (400ms) must elapse after that.
	for i := 0; i < 3; i++ {
		m.Tick(now.Add(time.Duration(i) * 100 * time.Millisecond))
		if m.State() != StateHealthy {
			t.Fatalf("premature state change at tick %d: %v", i, m.State())
		}
	}
	// 100ms + 500ms > DegradeAfter(400ms) → DEGRADED.
	m.Tick(now.Add(600 * time.Millisecond))
	if m.State() != StateDegraded {
		t.Fatalf("expected DEGRADED, got %v", m.State())
	}
	// Escalation: still over capacity for another DegradeAfter → DOWN.
	// The escalation timer starts at the DEGRADED transition (tick 600);
	// it must elapse DegradeAfter again.
	m.Tick(now.Add(1100 * time.Millisecond)) // timer starts here
	m.Tick(now.Add(1600 * time.Millisecond)) // 500ms > 400ms → DOWN
	if m.State() != StateDown {
		t.Fatalf("expected DOWN after escalation, got %v", m.State())
	}
}

// TestMissedProbesMarkDown: a dead link (no responses at all) goes DOWN via
// the missed-probe counter even before the loss EWMA escalates.
func TestMissedProbesMarkDown(t *testing.T) {
	m := New(fastOpts())
	for i := 0; i < 2; i++ {
		m.NoteMissedProbe()
		if m.State() != StateHealthy {
			t.Fatalf("premature DOWN after %d misses", i+1)
		}
	}
	m.NoteMissedProbe()
	if m.State() != StateDown {
		t.Fatalf("expected DOWN after 3 misses, got %v", m.State())
	}
}

// TestRevivalRequiresStability: a DOWN path revives only after responses
// resume AND loss stays low for RecoverAfter.
func TestLossSamplesDoNotConsumeRevival(t *testing.T) {
	m := New(Options{MaxLoss: 0.1, DegradeAfter: 300 * time.Millisecond})
	now := time.Now()
	// Path dies: 3 missed probes → DOWN. Loss samples interleave with
	// NoteMissedProbe exactly as the keepalive loop does.
	for i := 0; i < 3; i++ {
		m.NoteMissedProbe()
		m.ObserveSample(1, 0)
	}
	if m.State() != StateDown {
		t.Fatalf("expected DOWN, got %v", m.State())
	}
	// More loss samples while down (the path is still dead): the estimate
	// must rise toward 100%, and the revival flag must NOT be consumed.
	for i := 0; i < 10; i++ {
		m.NoteMissedProbe()
		m.ObserveSample(1, 0)
	}
	if got := m.Loss(); got < 0.9 {
		t.Fatalf("loss must be near 1.0 while down, got %v", got)
	}
	// Path revives: the first genuine response hard-resets the estimate…
	m.ObserveSample(0, 5*time.Millisecond)
	if got := m.Loss(); got != 0 {
		t.Fatalf("revival must reset loss to 0, got %v", got)
	}
	// …and recovery completes after RecoverAfter of stability.
	m.Tick(now)
	m.Tick(now.Add(11 * time.Second))
	if m.State() != StateHealthy {
		t.Fatalf("expected HEALTHY after stability window, got %v", m.State())
	}
}

// TestRevivalRequiresStability: a DOWN path revives only after responses
// resume AND loss stays low for RecoverAfter.
func TestRevivalRequiresStability(t *testing.T) {
	m := New(fastOpts())
	now := time.Now()
	// Kill it.
	for i := 0; i < 3; i++ {
		m.NoteMissedProbe()
	}
	if m.State() != StateDown {
		t.Fatalf("setup: expected DOWN, got %v", m.State())
	}
	// Link comes back: response hard-resets loss.
	m.ObserveSample(0, 20*time.Millisecond)
	if got := m.Loss(); got != 0 {
		t.Fatalf("revival must hard-reset loss, got %v", got)
	}
	// Not yet: stability window required.
	m.Tick(now.Add(100 * time.Millisecond))
	if m.State() != StateDown {
		t.Fatalf("revived too early: %v", m.State())
	}
	// Keep responding for RecoverAfter → HEALTHY.
	m.ObserveSample(0, 20*time.Millisecond)
	m.Tick(now.Add(700 * time.Millisecond))
	if m.State() != StateHealthy {
		t.Fatalf("expected HEALTHY after stability window, got %v", m.State())
	}
}

// TestDegradedRecovers: a path that was degraded returns to HEALTHY once
// loss drops below half the capacity for RecoverAfter.
func TestDegradedRecovers(t *testing.T) {
	m := New(fastOpts())
	now := time.Now()
	// Degrade it: two loss samples (α=0.5 → 0.75), then let the condition
	// mature over two ticks.
	for i := 0; i < 2; i++ {
		m.ObserveSample(1, 0)
	}
	m.Tick(now.Add(100 * time.Millisecond)) // condSince starts
	m.Tick(now.Add(600 * time.Millisecond)) // > DegradeAfter → DEGRADED
	if m.State() != StateDegraded {
		t.Fatalf("setup: expected DEGRADED, got %v", m.State())
	}
	// Clean up: decay with good samples (α_slow=0.1: 0.75·0.9³⁰ ≈ 0.03).
	for i := 0; i < 30; i++ {
		m.ObserveSample(0, 5*time.Millisecond)
	}
	if got := m.Loss(); got >= m.maxLoss*0.5 {
		t.Fatalf("loss did not decay below recovery threshold: %v", got)
	}
	m.Tick(now.Add(100 * time.Millisecond)) // recovery timer starts
	m.Tick(now.Add(700 * time.Millisecond)) // 600ms ≥ RecoverAfter → HEALTHY
	if m.State() != StateHealthy {
		t.Fatalf("expected HEALTHY after recovery window, got %v", m.State())
	}
}

// TestRTTAndJitterEstimates: EWMAs converge on the true values.
func TestRTTAndJitterEstimates(t *testing.T) {
	m := New(fastOpts())
	for i := 0; i < 50; i++ {
		m.ObserveSample(0, 40*time.Millisecond)
	}
	if rtt := m.RTT(); rtt < 30*time.Millisecond || rtt > 50*time.Millisecond {
		t.Fatalf("RTT estimate out of range: %v", rtt)
	}
	// Add jitter: alternating 20/60ms.
	m2 := New(fastOpts())
	for i := 0; i < 50; i++ {
		rtt := 20 * time.Millisecond
		if i%2 == 1 {
			rtt = 60 * time.Millisecond
		}
		m2.ObserveSample(0, rtt)
	}
	if j := m2.Jitter(); j <= 0 {
		t.Fatalf("jitter estimate did not react: %v", j)
	}
}
