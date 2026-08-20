package tunnel

// PFS integration tests (M5.5): the real client↔server pair must complete
// the X25519 key exchange over loopback and then pass data — and a client
// with a different PSK must never reach the established state.

import (
	"context"
	"testing"
	"time"

	"github.com/ColinFL/flexbraid/internal/config"
)

// TestPFSHandshakeEstablishes starts a real pair and asserts the client
// reaches the negotiated-session state (KEX_ACK processed) before data
// flows.
func TestPFSHandshakeEstablishes(t *testing.T) {
	_, cli, fakeWG, wgClient := startTestPair(t, "psk")
	_ = fakeWG // cleanup registered by the helper

	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, ready := cli.getSessionAEAD(); ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("client never established the PFS session over loopback")
		}
		time.Sleep(25 * time.Millisecond)
	}
	// Data must now traverse (proves both sides agree on the session key).
	sendUntilReceived(t, wgClient, mustUDPAddr(t, cli.ingress.LocalAddr().String()), fakeWG,
		[]byte("pfs-ok"), 5*time.Second)
}

// TestPFSWrongKeyNeverEstablishes: a client whose base key doesn't match the
// server's (wrong PSK) can never complete the exchange — its KEX_REQ fails
// authentication server-side, so no KEX_ACK comes back and the client stays
// unestablished (data never flows). This is the PFS-specific assertion on
// top of TestTunnelRejectsWrongPSK's wire-level check.
func TestPFSWrongKeyNeverEstablishes(t *testing.T) {
	srv, _, _, _ := startTestPair(t, "correct-psk")
	_ = srv

	evilCfg := &config.Config{
		Mode:   config.ModeClient,
		Listen: "127.0.0.1:0",
		Server: srv.LocalAddr().String(),
		Crypto: config.Crypto{Key: "wrong-psk", Cipher: "chacha20poly1305"},
		WANs: []config.WAN{{
			ID: "w1", Transport: config.TransportUDP, CapacityMbps: 100,
		}},
	}
	evil, err := NewClient(evilCfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := evil.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = evil.Run(ctx) }()

	deadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, ready := evil.getSessionAEAD(); ready {
			t.Fatal("wrong-PSK client established a session — PFS auth broken")
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Sanity: the base key derivation itself is what gates this.
	if _, ready := evil.getSessionAEAD(); ready {
		t.Fatal("wrong-PSK client established a session")
	}
}
