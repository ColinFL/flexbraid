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

func mustUDPAddr(t *testing.T, s string) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", s)
	if err != nil {
		t.Fatalf("resolve %q: %v", s, err)
	}
	return addr
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

// startTestPair spins up a server + client pair over loopback and returns
// them plus the fake WG peer. Both are already Start()ed and running.
func startTestPair(t *testing.T, psk string) (srv *Server, cli *Client, fakeWG, wgClient *net.UDPConn) {
	t.Helper()
	log := testLogger()

	fakeWG, err := net.ListenUDP("udp", mustUDPAddr(t, "127.0.0.1:0"))
	if err != nil {
		t.Fatalf("fake wg listen: %v", err)
	}
	t.Cleanup(func() { fakeWG.Close() })

	srvCfg := &config.Config{
		Mode:   config.ModeServer,
		Listen: "127.0.0.1:0",
		WGPeer: fakeWG.LocalAddr().String(),
		Crypto: config.Crypto{Key: psk, Cipher: "chacha20poly1305"},
	}
	srv, err = NewServer(srvCfg, log)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("server start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Run(ctx) }()

	cliCfg := &config.Config{
		Mode:   config.ModeClient,
		Listen: "127.0.0.1:0",
		Server: srv.LocalAddr().String(),
		Crypto: config.Crypto{Key: psk, Cipher: "chacha20poly1305"},
		WANs: []config.WAN{{
			ID: "w1", Transport: config.TransportUDP, CapacityMbps: 100,
		}},
	}
	cli, err = NewClient(cliCfg, log)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := cli.Start(); err != nil {
		t.Fatalf("client start: %v", err)
	}
	go func() { _ = cli.Run(ctx) }()

	wgClient, err = net.ListenUDP("udp", mustUDPAddr(t, "127.0.0.1:0"))
	if err != nil {
		t.Fatalf("wg client listen: %v", err)
	}
	t.Cleanup(func() { wgClient.Close() })
	return srv, cli, fakeWG, wgClient
}

// TestTunnelBidirectionalRoundTrip spins up a real server + client pair over
// loopback UDP and verifies an inner datagram (WireGuard-style) traverses
// both directions with the session handshake in between.
func TestTunnelBidirectionalRoundTrip(t *testing.T) {
	_, cli, fakeWG, wgClient := startTestPair(t, "integration-test-psk")

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
	srv, _, fakeWG, wgClient := startTestPair(t, "correct-psk")

	// Evil client: same everything, wrong key.
	evilCfg := &config.Config{
		Mode:   config.ModeClient,
		Listen: "127.0.0.1:0",
		Server: srv.LocalAddr().String(),
		Crypto: config.Crypto{Key: "wrong-psk", Cipher: "chacha20poly1305"},
		WANs: []config.WAN{{
			ID: "w1", Transport: config.TransportUDP, CapacityMbps: 100,
		}},
	}
	evilCli, err := NewClient(evilCfg, testLogger())
	if err != nil {
		t.Fatalf("new evil client: %v", err)
	}
	if err := evilCli.Start(); err != nil {
		t.Fatalf("evil client start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = evilCli.Run(ctx) }()

	// Send for 2 seconds; nothing may ever reach the fake WG peer.
	deadline := time.Now().Add(2 * time.Second)
	buf := make([]byte, 65535)
	sent := false
	for time.Now().Before(deadline) {
		if _, err := wgClient.WriteToUDP([]byte("sneak"), evilCli.LocalAddr()); err != nil {
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

// TestServerStartFailsOnBusyPort proves that init errors surface
// synchronously from Start() instead of panicking in a goroutine.
func TestServerStartFailsOnBusyPort(t *testing.T) {
	occ, err := net.ListenUDP("udp", mustUDPAddr(t, "127.0.0.1:0"))
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer occ.Close()

	cfg := &config.Config{
		Mode:   config.ModeServer,
		Listen: occ.LocalAddr().String(), // already taken
		WGPeer: "127.0.0.1:9",
		Crypto: config.Crypto{Key: "psk", Cipher: "chacha20poly1305"},
	}
	srv, err := NewServer(cfg, testLogger())
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.Start(); err == nil {
		t.Fatal("Start must fail when the listen port is busy")
	}
}

// TestClientStartFailsOnBusyPort is the client-side counterpart.
func TestClientStartFailsOnBusyPort(t *testing.T) {
	occ, err := net.ListenUDP("udp", mustUDPAddr(t, "127.0.0.1:0"))
	if err != nil {
		t.Fatalf("occupy port: %v", err)
	}
	defer occ.Close()

	cfg := &config.Config{
		Mode:   config.ModeClient,
		Listen: occ.LocalAddr().String(), // already taken
		Server: "127.0.0.1:9",
		Crypto: config.Crypto{Key: "psk", Cipher: "chacha20poly1305"},
		WANs: []config.WAN{{
			ID: "w1", Transport: config.TransportUDP, CapacityMbps: 100,
		}},
	}
	cli, err := NewClient(cfg, testLogger())
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := cli.Start(); err == nil {
		t.Fatal("Start must fail when the ingress port is busy")
	}
}
