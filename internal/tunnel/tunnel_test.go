package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/ColinFL/flexbraid/internal/config"
)

// testLogger silences the tunnel's own logging during tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// waitFor polls fn until it returns true or the timeout elapses.
func waitFor(t *testing.T, what string, fn func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// sendUntilReceived sends payload from src to dst repeatedly (UDP is
// lossy and the tunnel handshake is asynchronous) until the packet shows up
// on sink. It returns the address sink observed as the sender.
func sendUntilReceived(t *testing.T, src *net.UDPConn, dst *net.UDPAddr, sink *net.UDPConn, payload []byte, timeout time.Duration) *net.UDPAddr {
	t.Helper()
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		if _, err := src.WriteToUDP(payload, dst); err != nil {
			t.Fatalf("write: %v", err)
		}
		for {
			_ = sink.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
			n, addr, err := sink.ReadFromUDP(buf)
			if err != nil {
				break // timeout on this read; retry the send
			}
			if string(buf[:n]) == string(payload) {
				return addr
			}
		}
	}
	t.Fatalf("timed out waiting for %q to traverse the tunnel", string(payload))
	return nil
}

// expectUDP waits for exactly want to arrive on conn.
func expectUDP(t *testing.T, conn *net.UDPConn, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	buf := make([]byte, 65535)
	for time.Now().Before(deadline) {
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, _, err := conn.ReadFromUDP(buf)
		if err == nil && string(buf[:n]) == want {
			return
		}
	}
	t.Fatalf("timed out waiting for %q", want)
}

// TestTunnelBidirectionalRoundTrip spins up a real server + client pair over
// loopback UDP and verifies an inner datagram (WireGuard-style) traverses
// both directions with the session handshake in between.
func TestTunnelBidirectionalRoundTrip(t *testing.T) {
	log := testLogger()

	// Fake WireGuard peer: the server's egress target.
	fakeWG, err := net.ListenUDP("udp", mustUDPAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("fake wg listen: %v", err)
	}
	defer fakeWG.Close()

	// Server.
	serverCfg := &config.Config{
		Mode:   config.ModeServer,
		Listen: "127.0.0.1:0",
		WGPeer: fakeWG.LocalAddr().String(),
		Crypto: config.Crypto{Key: "integration-test-psk", Cipher: "chacha20poly1305"},
	}
	srv, err := NewServer(serverCfg, log)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()
	waitFor(t, "server wan socket", func() bool { return srv.LocalAddr() != nil }, 3*time.Second)

	// Client.
	clientCfg := &config.Config{
		Mode:   config.ModeClient,
		Listen: "127.0.0.1:0",
		Server: srv.LocalAddr().String(),
		Crypto: config.Crypto{Key: "integration-test-psk", Cipher: "chacha20poly1305"},
		WANs: []config.WAN{{
			ID: "w1", Transport: config.TransportUDP, CapacityMbps: 100,
		}},
	}
	cli, err := NewClient(clientCfg, log)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	go func() { _ = cli.Run(ctx) }()
	waitFor(t, "client ingress socket", func() bool { return cli.LocalAddr() != nil }, 3*time.Second)

	// Inner WireGuard client socket.
	wgClient, err := net.ListenUDP("udp", mustUDPAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("wg client listen: %v", err)
	}
	defer wgClient.Close()

	// Client → server: "ping" must arrive at the fake WG peer.
	egressAddr := sendUntilReceived(t, wgClient, cli.LocalAddr(), fakeWG, []byte("ping"), 6*time.Second)

	// Server → client: WG peer replies "pong" to the egress socket it saw;
	// it must arrive back at the inner WG client.
	if _, err := fakeWG.WriteToUDP([]byte("pong"), egressAddr); err != nil {
		t.Fatalf("fake wg reply: %v", err)
	}
	expectUDP(t, wgClient, "pong", 3*time.Second)
}

// TestTunnelRejectsWrongPSK verifies that a client with a different key can
// never establish a session: its handshake is authenticated and refused.
func TestTunnelRejectsWrongPSK(t *testing.T) {
	log := testLogger()

	fakeWG, err := net.ListenUDP("udp", mustUDPAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("fake wg listen: %v", err)
	}
	defer fakeWG.Close()

	serverCfg := &config.Config{
		Mode:   config.ModeServer,
		Listen: "127.0.0.1:0",
		WGPeer: fakeWG.LocalAddr().String(),
		Crypto: config.Crypto{Key: "correct-psk", Cipher: "chacha20poly1305"},
	}
	srv, err := NewServer(serverCfg, log)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Run(ctx) }()
	waitFor(t, "server wan socket", func() bool { return srv.LocalAddr() != nil }, 3*time.Second)

	// Evil client with the wrong key.
	clientCfg := &config.Config{
		Mode:   config.ModeClient,
		Listen: "127.0.0.1:0",
		Server: srv.LocalAddr().String(),
		Crypto: config.Crypto{Key: "wrong-psk", Cipher: "chacha20poly1305"},
		WANs: []config.WAN{{
			ID: "w1", Transport: config.TransportUDP, CapacityMbps: 100,
		}},
	}
	cli, err := NewClient(clientCfg, log)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	go func() { _ = cli.Run(ctx) }()
	waitFor(t, "client ingress socket", func() bool { return cli.LocalAddr() != nil }, 3*time.Second)

	wgClient, err := net.ListenUDP("udp", mustUDPAddr("127.0.0.1:0"))
	if err != nil {
		t.Fatalf("wg client listen: %v", err)
	}
	defer wgClient.Close()

	// Send for 2 seconds; nothing may ever reach the fake WG peer.
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 65535)
	sent := false
	for time.Now().Before(deadline) {
		if _, err := wgClient.WriteToUDP([]byte("sneak"), cli.LocalAddr()); err != nil {
			t.Fatalf("write: %v", err)
		}
		sent = true
		_ = fakeWG.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		if _, _, err := fakeWG.ReadFromUDP(buf); err == nil {
			t.Fatalf("wrong-key traffic reached the WG peer — auth broken")
		}
	}
	if !sent {
		t.Fatal("test setup broken: no packets sent")
	}
}
