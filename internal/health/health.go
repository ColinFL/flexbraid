// Package health implements per-path quality monitoring and the circuit
// breaker (docs/DESIGN.md §8).
//
// Each WAN has a Monitor. It estimates loss with a fast-rise / slow-decay
// EWMA (the "exponential weight" of the design): a spike in loss moves the
// estimate up almost immediately, while recovery decays it slowly — so a
// flaky path is pulled out of rotation fast and only returns after sustained
// stability. RTT and jitter are tracked with plain EWMAs.
//
// State machine (hysteresis):
//
//	HEALTHY ──(missed probes ≥ downAfterMisses)──────────────────► DOWN
//	HEALTHY ──(loss > maxLoss for degradeAfter)──────────────────► DEGRADED
//	DEGRADED ──(missed probes ≥ downAfterMisses)─────────────────► DOWN
//	DEGRADED ──(loss > maxLoss for degradeAfter, escalation)─────► DOWN
//	DEGRADED ──(loss < maxLoss*0.5 for recoverAfter)─────────────► HEALTHY
//	DOWN ──────(responses resume; loss < maxLoss*0.5 for recoverAfter)─► HEALTHY
package health

import (
	"sync"
	"time"
)

// State is the circuit-breaker state of one path.
type State int

const (
	// StateHealthy — the path carries traffic normally.
	StateHealthy State = iota
	// StateDegraded — loss exceeds what FEC can compensate; the scheduler
	// should stop sending new work and drain in-flight frames.
	StateDegraded
	// StateDown — the path is considered dead; only probes are sent.
	StateDown
)

func (s State) String() string {
	switch s {
	case StateHealthy:
		return "healthy"
	case StateDegraded:
		return "degraded"
	case StateDown:
		return "down"
	}
	return "unknown"
}

// Options tunes one Monitor. Zero values fall back to sane defaults.
type Options struct {
	// MaxLoss is the loss fraction above which the path is considered
	// non-compensable (typically the FEC repair capacity). 0 < MaxLoss < 1.
	MaxLoss float64
	// DegradeAfter is how long loss must exceed MaxLoss before the path is
	// marked DEGRADED (default 3s).
	DegradeAfter time.Duration
	// RecoverAfter is how long loss must stay below MaxLoss*0.5 before a
	// degraded or down path returns to HEALTHY (default 10s).
	RecoverAfter time.Duration
	// DownAfterMisses is the number of consecutive unanswered probes that
	// mark the path DOWN (default 3).
	DownAfterMisses int
	// DownGrace is a debounce applied before the DOWN transition once the
	// missed-probe threshold is reached (anti-flap on jittery links).
	// 0 = transition immediately, as before.
	DownGrace time.Duration
	// LossAlphaFast is the EWMA weight applied when a sample is worse than
	// the current estimate (rise; default 0.4).
	LossAlphaFast float64
	// LossAlphaSlow is the EWMA weight applied when a sample is better than
	// the current estimate (decay; default 0.03).
	LossAlphaSlow float64
	// JitterAlpha is the EWMA weight for RTT jitter (default 0.1).
	JitterAlpha float64
}

// Monitor tracks one path's quality and circuit-breaker state.
type Monitor struct {
	maxLoss     float64
	degradeAft  time.Duration
	recoverAft  time.Duration
	downAftMiss int
	downGrace   time.Duration
	alphaFast   float64
	alphaSlow   float64
	jitterAlpha float64

	mu        sync.Mutex
	loss      float64 // EWMA, 0..1
	rtt       time.Duration
	jitter    time.Duration
	state     State
	misses    int // consecutive unanswered probes
	missSince time.Time
	condSince time.Time
	revived   bool // a DOWN path has answered at least one probe again
	// inBandBad counts consecutive in-band windows whose unrecovered loss
	// exceeded the FEC capacity (ObserveInBand); 2 bad windows trip an
	// immediate DEGRADED.
	inBandBad int
}

// New builds a Monitor with the given options (defaults filled in).
func New(opts Options) *Monitor {
	if opts.MaxLoss <= 0 || opts.MaxLoss >= 1 {
		opts.MaxLoss = 0.2
	}
	if opts.DegradeAfter <= 0 {
		opts.DegradeAfter = 3 * time.Second
	}
	if opts.RecoverAfter <= 0 {
		opts.RecoverAfter = 10 * time.Second
	}
	if opts.DownAfterMisses <= 0 {
		opts.DownAfterMisses = 3
	}
	if opts.DownGrace < 0 {
		opts.DownGrace = 0
	}
	if opts.LossAlphaFast <= 0 || opts.LossAlphaFast >= 1 {
		opts.LossAlphaFast = 0.4
	}
	if opts.LossAlphaSlow <= 0 || opts.LossAlphaSlow >= 1 {
		opts.LossAlphaSlow = 0.03
	}
	if opts.JitterAlpha <= 0 || opts.JitterAlpha >= 1 {
		opts.JitterAlpha = 0.1
	}
	return &Monitor{
		maxLoss:     opts.MaxLoss,
		degradeAft:  opts.DegradeAfter,
		recoverAft:  opts.RecoverAfter,
		downAftMiss: opts.DownAfterMisses,
		downGrace:   opts.DownGrace,
		alphaFast:   opts.LossAlphaFast,
		alphaSlow:   opts.LossAlphaSlow,
		jitterAlpha: opts.JitterAlpha,
		state:       StateHealthy,
	}
}

// ObserveSample records one probe outcome: loss is 0 (answered) or 1
// (missed). A positive rtt updates the RTT/jitter estimates. Only a genuine
// response (rtt > 0) resets the missed-probe counter and hard-resets a DOWN
// path — a loss sample must NOT consume the revival flag, or the path would
// come back with a stale ~100% loss estimate and never recover (the slow
// decay would take minutes to cross the recovery threshold).
func (m *Monitor) ObserveSample(loss float64, rtt time.Duration) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if loss > m.loss {
		m.loss += m.alphaFast * (loss - m.loss)
	} else {
		m.loss += m.alphaSlow * (loss - m.loss)
	}
	if rtt > 0 {
		delta := rtt - m.rtt
		if delta < 0 {
			delta = -delta
		}
		if m.rtt == 0 {
			m.rtt = rtt
		} else {
			m.rtt += time.Duration(m.jitterAlpha * float64(rtt-m.rtt))
		}
		m.jitter += time.Duration(m.jitterAlpha * float64(delta-m.jitter))
		m.noteAliveLocked()
	}
}

// NoteAlive records that the path answered — any authenticated frame counts
// (data, keepalive, PONG). It resets the missed-probe counter and
// hard-resets a DOWN path on its first response, without touching the
// RTT/jitter estimates. This is the liveness signal for paths where RTT is
// not measurable (e.g. the server side, which only sees keepalive arrivals).
func (m *Monitor) NoteAlive() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.noteAliveLocked()
}

// noteAliveLocked is the shared response bookkeeping: a response means the
// path is alive again.
func (m *Monitor) noteAliveLocked() {
	m.misses = 0
	m.missSince = time.Time{}
	if m.state == StateDown && !m.revived {
		// Hard reset on the first response after DOWN: the link is
		// back, forget its dead past. Subsequent responses must NOT
		// reset the recovery timer (revived stays true), or the path
		// would never leave DOWN in steady state.
		m.revived = true
		m.loss = 0
		m.condSince = time.Time{}
	}
}

// NoteMissedProbe records an unanswered probe. Enough consecutive misses
// mark the path DOWN — immediately (down_grace_sec = 0, the default) or
// after the debounce window elapses, so a flapping link does not slam the
// scheduler between states.
func (m *Monitor) NoteMissedProbe() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.misses++
	if m.misses >= m.downAftMiss {
		if m.downGrace <= 0 {
			if m.state != StateDown {
				m.setState(StateDown)
			}
		} else if m.missSince.IsZero() {
			m.missSince = time.Now()
		}
	}
}

// ObserveInBand feeds the monitor from the FEC decoder's unrecovered-loss
// rate on this path (lost/(lost+received) over the last window). Unlike
// probes this signal is immediate under load: two consecutive windows whose
// loss exceeds the FEC capacity force an instant HEALTHY → DEGRADED, so the
// scheduler stops loading a path that FEC can no longer protect — no need
// to wait for the probe-based DegradeAfter hysteresis.
func (m *Monitor) ObserveInBand(lossRate float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if lossRate > m.loss {
		m.loss += m.alphaFast * (lossRate - m.loss)
	} else {
		m.loss += m.alphaSlow * (lossRate - m.loss)
	}
	if lossRate > m.maxLoss {
		m.inBandBad++
		if m.inBandBad >= 2 && m.state == StateHealthy {
			m.setState(StateDegraded)
		}
	} else {
		m.inBandBad = 0
	}
}

// Tick advances the state machine. Call it from the tunnel's ticker.
func (m *Monitor) Tick(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tickLocked(now)
}

func (m *Monitor) tickLocked(now time.Time) {
	// Condition timers: condSince tracks when the *current condition*
	// started (not the state), so hysteresis uses sustained measurements.
	// missedDown reports whether the missed-probe threshold is met,
	// honouring the DOWN debounce window.
	missedDown := m.misses >= m.downAftMiss &&
		(m.downGrace <= 0 || (!m.missSince.IsZero() && now.Sub(m.missSince) >= m.downGrace))
	switch m.state {
	case StateHealthy:
		if missedDown {
			m.setState(StateDown)
			return
		}
		if m.loss > m.maxLoss {
			if m.condSince.IsZero() {
				m.condSince = now
			} else if now.Sub(m.condSince) >= m.degradeAft {
				m.setState(StateDegraded)
			}
		} else {
			m.condSince = time.Time{}
		}
	case StateDegraded:
		if missedDown {
			m.setState(StateDown)
			return
		}
		if m.loss > m.maxLoss {
			// Escalation: still over capacity — drop to DOWN.
			if m.condSince.IsZero() {
				m.condSince = now
			} else if now.Sub(m.condSince) >= m.degradeAft {
				m.setState(StateDown)
			}
		} else if m.loss < m.maxLoss*0.5 {
			if m.condSince.IsZero() {
				m.condSince = now
			} else if now.Sub(m.condSince) >= m.recoverAft {
				m.setState(StateHealthy)
			}
		} else {
			m.condSince = time.Time{}
		}
	case StateDown:
		// The path answers probes again (ObserveSample hard-reset loss),
		// now it must stay stable for recoverAfter before returning.
		if m.loss < m.maxLoss*0.5 {
			if m.condSince.IsZero() {
				m.condSince = now
			} else if now.Sub(m.condSince) >= m.recoverAft {
				m.setState(StateHealthy)
			}
		} else {
			m.condSince = time.Time{}
		}
	}
}

func (m *Monitor) setState(s State) {
	m.state = s
	m.condSince = time.Time{}
	m.revived = false
}

// State returns the current circuit-breaker state.
func (m *Monitor) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

// Loss returns the current EWMA loss estimate (0..1).
func (m *Monitor) Loss() float64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loss
}

// RTT returns the current EWMA round-trip time.
func (m *Monitor) RTT() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rtt
}

// Jitter returns the current EWMA jitter estimate.
func (m *Monitor) Jitter() time.Duration {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.jitter
}
