package health

import (
	"fmt"
	"testing"
	"time"
)

func TestDebugDownRecovery(t *testing.T) {
	m := New(Options{MaxLoss: 0.1, DegradeAfter: 300 * time.Millisecond})
	now := time.Now()
	for i := 0; i < 3; i++ {
		m.NoteMissedProbe()
	}
	fmt.Printf("state=%v loss=%.3f recoverAft=%v\n", m.State(), m.Loss(), m.recoverAft)
	for i := 0; i < 70; i++ {
		m.ObserveSample(0, 5*time.Millisecond)
		now = now.Add(200 * time.Millisecond)
		m.Tick(now)
		if i%10 == 0 {
			fmt.Printf("t+%ds state=%v loss=%.3f\n", (i+1)/5, m.State(), m.Loss())
		}
	}
}
