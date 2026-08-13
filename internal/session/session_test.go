package session

import (
	"net"
	"testing"

	"github.com/ColinFL/flexbraid/internal/crypto"
)

func TestPerPathEndpoints(t *testing.T) {
	s := NewServerSession(42)

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
	s := NewServerSession(1)

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

func TestManagerGetOrCreate(t *testing.T) {
	m := NewManager()
	a := m.GetOrCreate(7)
	b := m.GetOrCreate(7)
	if a != b {
		t.Fatal("GetOrCreate must return the same session for the same ID")
	}
	if m.Get(8) != nil {
		t.Fatal("unknown session must be nil")
	}
	if len(m.All()) != 1 {
		t.Fatalf("want 1 session, got %d", len(m.All()))
	}
}
