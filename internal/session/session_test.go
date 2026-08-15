package session

import (
	"crypto/cipher"
	"net"
	"testing"
	"time"

	"github.com/ColinFL/flexbraid/internal/crypto"
)

// TestCheckFirstReplay: a replayed handshake seq is rejected before any
// session state exists; windows expire via ExpireFirsts.
func TestCheckFirstReplay(t *testing.T) {
	m := NewManager()
	const id = ID(7)

	if !m.CheckFirstReplay(id, 100) {
		t.Fatal("first sight of a seq must be accepted")
	}
	if m.CheckFirstReplay(id, 100) {
		t.Fatal("replayed handshake seq must be rejected")
	}
	if !m.CheckFirstReplay(id, 101) {
		t.Fatal("a fresh seq must be accepted")
	}
	// Expiry: after ExpireFirsts the window is gone and the seq is
	// accepted again (fresh window semantics). Negative TTL: on Windows
	// time.Now() may return the same tick for both calls, so a zero TTL
	// is unreliable (see TestManagerExpire).
	m.ExpireFirsts(-time.Second)
	if !m.CheckFirstReplay(id, 100) {
		t.Fatal("post-expiry window must accept the seq again")
	}
}

// TestCheckFirstReplayBounded: the handshake table stays bounded even under
// a flood of distinct session IDs (the oldest entry is evicted).
func TestCheckFirstReplayBounded(t *testing.T) {
	m := NewManager()
	for i := 0; i < maxFirstWindows+100; i++ {
		if !m.CheckFirstReplay(ID(i+1), 1) {
			t.Fatalf("fresh id %d rejected", i+1)
		}
	}
	m.mu.Lock()
	n := len(m.firstWindows)
	m.mu.Unlock()
	if n > maxFirstWindows {
		t.Fatalf("firstWindows grew to %d, cap is %d", n, maxFirstWindows)
	}
}

func testAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	key, err := crypto.DeriveKey([]byte("test-psk"))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	aead, err := crypto.NewAEAD(key, "chacha20poly1305")
	if err != nil {
		t.Fatalf("aead: %v", err)
	}
	return aead
}

func TestPerPathEndpoints(t *testing.T) {
	s := NewServerSession(42, testAEAD(t))

	s.SetEndpoint("w1", &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 1111})
	s.SetEndpoint("w2", &net.UDPAddr{IP: net.IPv4(192, 0, 2, 2), Port: 2222})
	// Same path, new address (NAT re-mapping after WAN switch).
	s.SetEndpoint("w1", &net.UDPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 3333})

	eps := s.Endpoints()
	if len(eps) != 2 {
		t.Fatalf("want 2 endpoints, got %d: %v", len(eps), eps)
	}
	if eps["w1"].Port != 3333 {
		t.Errorf("w1 endpoint not updated: %v", eps["w1"])
	}
	if eps["w2"].Port != 2222 {
		t.Errorf("w2 endpoint wrong: %v", eps["w2"])
	}
}

func TestReplayWindowRejectsReplaysAndOldSeqs(t *testing.T) {
	s := NewServerSession(1, testAEAD(t))

	if !s.CheckReplay(1) || !s.CheckReplay(2) || !s.CheckReplay(3) {
		t.Fatal("fresh seqs must be accepted")
	}
	if s.CheckReplay(2) {
		t.Fatal("replayed seq accepted")
	}
	if s.CheckReplay(1) {
		t.Fatal("old seq accepted")
	}
	// Jump far ahead: the window slides, old seqs fall out and must be
	// rejected, while brand-new in-window seqs stay accepted.
	if !s.CheckReplay(5000) {
		t.Fatal("window must slide forward for new seqs")
	}
	base := uint32(5000) - crypto.DefaultReplayWindow + 1 // new window base
	if s.CheckReplay(base - 1) {
		t.Fatal("seq before the slid window accepted")
	}
	if !s.CheckReplay(base) {
		t.Fatal("in-window seq after the slide must be accepted")
	}
	if s.CheckReplay(5000) {
		t.Fatal("replay of the sliding seq accepted")
	}
}

func TestManagerPutGetDelete(t *testing.T) {
	m := NewManager()
	s := NewServerSession(7, testAEAD(t))
	m.Put(s)
	if m.Get(7) != s {
		t.Fatal("Get must return the stored session")
	}
	if m.Count() != 1 {
		t.Fatalf("want 1 session, got %d", m.Count())
	}
	m.Delete(7)
	if m.Get(7) != nil {
		t.Fatal("session must be gone after Delete")
	}
	if m.Count() != 0 {
		t.Fatalf("want 0 sessions, got %d", m.Count())
	}
}

func TestManagerExpire(t *testing.T) {
	m := NewManager()
	m.Put(NewServerSession(1, testAEAD(t)))
	m.Put(NewServerSession(2, testAEAD(t)))

	// Negative TTL: cutoff is in the future, so every session is idle.
	// (A zero TTL is unreliable: time.Now() has ~100ns resolution on
	// Windows, and the sessions may have been created in the same tick.)
	if n := m.Expire(-time.Second); n != 2 {
		t.Fatalf("want 2 expired, got %d", n)
	}
	if m.Count() != 0 {
		t.Fatalf("want 0 sessions after expire, got %d", m.Count())
	}
}

func TestManagerExpireKeepsFresh(t *testing.T) {
	m := NewManager()
	s := NewServerSession(1, testAEAD(t))
	m.Put(s)

	// Fresh session (created just now) must survive a long TTL.
	if n := m.Expire(time.Hour); n != 0 {
		t.Fatalf("fresh session expired: %d", n)
	}
	if m.Get(1) == nil {
		t.Fatal("fresh session lost")
	}
}
