package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ColinFL/flexbraid/internal/config"
	"github.com/ColinFL/flexbraid/internal/fec"
	"github.com/ColinFL/flexbraid/internal/frame"
	"github.com/ColinFL/flexbraid/internal/health"
	"github.com/ColinFL/flexbraid/internal/transport"
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
	return startTestPairWithFEC(t, psk, nil)
}

// startTestPairWithFEC is startTestPair with an explicit FEC configuration.
func startTestPairWithFEC(t *testing.T, psk string, fecCfg *config.FEC) (srv *Server, cli *Client, fakeWG, wgClient *net.UDPConn) {
	t.Helper()
	return startTestPairWrapped(t, psk, fecCfg, nil)
}

// startTestPairWrapped additionally wraps the client's WAN transport before
// the tunnel starts (e.g. to inject loss). The wrapper must be safe to
// install pre-start; runtime toggling must use atomic state.
func startTestPairWrapped(t *testing.T, psk string, fecCfg *config.FEC, wrap func(transport.Transport) transport.Transport) (srv *Server, cli *Client, fakeWG, wgClient *net.UDPConn) {
	t.Helper()
	log := testLogger()
	fecOpt := config.FEC{}
	if fecCfg != nil {
		fecOpt = *fecCfg
	}

	fakeWG, err := net.ListenUDP("udp", mustUDPAddr(t, "127.0.0.1:0"))
	if err != nil {
		t.Fatalf("fake wg listen: %v", err)
	}
	t.Cleanup(func() { fakeWG.Close() })

	srvCfg := &config.Config{
		Mode:   config.ModeServer,
		Listen: "127.0.0.1:0",
		WGPeer: fakeWG.LocalAddr().String(),
		FEC:    fecOpt,
		Crypto: config.Crypto{Key: psk, Cipher: "chacha20poly1305"},
	}
	// With FEC on, the largest parity frame must fit the 1500-byte path MTU
	// (P2): inner MTU 1390 = 1500 − 28 (frame hdr) − 16 (AEAD) − 66 (parity
	// sub-header, k=10). Config validation rejects anything larger.
	if fecOpt.Enabled {
		srvCfg.MTU = 1390
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
		FEC:    fecOpt,
		Crypto: config.Crypto{Key: psk, Cipher: "chacha20poly1305"},
		WANs: []config.WAN{{
			ID: "w1", Transport: config.TransportUDP, CapacityMbps: 100,
		}},
	}
	if fecOpt.Enabled {
		cliCfg.MTU = 1390
	}
	cli, err = NewClient(cliCfg, log)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if wrap != nil {
		cli.wans[0].tr = wrap(cli.wans[0].tr)
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

// lossyTransport wraps a Transport and drops frames on Send once enabled: it
// models a lossy WAN (dropEvery) or a fully dead WAN (killAll). The wrapper
// must be installed before the tunnel starts; toggles are atomic. sends
// counts every frame handed to Send.
type lossyTransport struct {
	inner     transport.Transport
	dropEvery int
	enabled   atomic.Bool
	killAll   atomic.Bool
	sends     atomic.Uint64
	mu        sync.Mutex
	count     int
}

func (l *lossyTransport) ID() string                           { return l.inner.ID() }
func (l *lossyTransport) Open() error                          { return l.inner.Open() }
func (l *lossyTransport) LocalAddr() net.Addr                  { return l.inner.LocalAddr() }
func (l *lossyTransport) SendTo(addr net.Addr, b []byte) error { return l.inner.SendTo(addr, b) }
func (l *lossyTransport) Recv() ([]byte, net.Addr, error)      { return l.inner.Recv() }
func (l *lossyTransport) Close() error                         { return l.inner.Close() }

func (l *lossyTransport) Send(b []byte) error {
	l.sends.Add(1)
	if l.killAll.Load() {
		return nil // the WAN is dead: every frame is swallowed
	}
	if !l.enabled.Load() {
		return l.inner.Send(b)
	}
	l.mu.Lock()
	l.count++
	drop := l.count%l.dropEvery == 0
	l.mu.Unlock()
	if drop {
		return nil // silently drop: the WAN ate the frame
	}
	return l.inner.Send(b)
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

// TestTunnelFECSurvivesPacketLoss proves FEC end-to-end: with 25% of frames
// dropped on the WAN, the Reed–Solomon redundancy must recover every single
// inner datagram (no retries from the sender side).
func TestTunnelFECSurvivesPacketLoss(t *testing.T) {
	lossy := &lossyTransport{dropEvery: 4}
	lossy.enabled.Store(false)
	srv, cli, fakeWG, wgClient := startTestPairWrapped(t, "fec-psk", &config.FEC{
		Enabled:          true,
		Mode:             config.FECFixed,
		FixedOverheadPct: 40, // k=10, parity=4 → covers up to 4 losses/block
		BlockTimeoutMS:   100,
	}, func(inner transport.Transport) transport.Transport {
		lossy.inner = inner
		return lossy
	})

	// Wait for the handshake to establish the session (loss still off, so
	// the FIRST frame is guaranteed to arrive).
	waitFor(t, "server session", func() bool { return srv.mgr.Count() == 1 }, 3*time.Second)

	// Now inject 25% loss on the client → server direction.
	lossy.enabled.Store(true)

	const n = 30
	for i := 0; i < n; i++ {
		if _, err := wgClient.WriteToUDP([]byte(fmt.Sprintf("ping-%02d", i)), cli.LocalAddr()); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		time.Sleep(2 * time.Millisecond)
	}

	// Every ping must arrive at the WG peer despite the 25% frame loss.
	got := make(map[string]bool)
	buf := make([]byte, 65535)
	deadline := time.Now().Add(5 * time.Second)
	for len(got) < n && time.Now().Before(deadline) {
		_ = fakeWG.SetReadDeadline(time.Now().Add(250 * time.Millisecond))
		nn, _, err := fakeWG.ReadFromUDP(buf)
		if err == nil {
			got[string(buf[:nn])] = true
		}
	}
	if len(got) != n {
		t.Fatalf("only %d/%d pings survived 25%% frame loss — FEC failed: %v", len(got), n, got)
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

// TestTwoClientsIsolated verifies per-session egress (P1): with two clients
// on one server, each session must have its own egress socket to the WG
// peer (observable as distinct source addresses at the peer), and replies
// must be routed back only to the session that owns them.
func TestTwoClientsIsolated(t *testing.T) {
	srv, cli1, fakeWG, wgClient1 := startTestPair(t, "multi-client-psk")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Second client on the same server, its own inner WG socket.
	cli2Cfg := &config.Config{
		Mode:   config.ModeClient,
		Listen: "127.0.0.1:0",
		Server: srv.LocalAddr().String(),
		Crypto: config.Crypto{Key: "multi-client-psk", Cipher: "chacha20poly1305"},
		WANs: []config.WAN{{
			ID: "w1", Transport: config.TransportUDP, CapacityMbps: 100,
		}},
	}
	cli2, err := NewClient(cli2Cfg, testLogger())
	if err != nil {
		t.Fatalf("new client 2: %v", err)
	}
	if err := cli2.Start(); err != nil {
		t.Fatalf("client 2 start: %v", err)
	}
	go func() { _ = cli2.Run(ctx) }()
	wgClient2, err := net.ListenUDP("udp", mustUDPAddr(t, "127.0.0.1:0"))
	if err != nil {
		t.Fatalf("wg client 2 listen: %v", err)
	}
	t.Cleanup(func() { wgClient2.Close() })

	// Each client's ping must reach the WG peer from a DISTINCT egress
	// socket. The P1 regression: the old shared-socket design shows one
	// source for both.
	src1 := sendUntilReceived(t, wgClient1, cli1.LocalAddr(), fakeWG, []byte("ping-1"), 6*time.Second)
	src2 := sendUntilReceived(t, wgClient2, cli2.LocalAddr(), fakeWG, []byte("ping-2"), 6*time.Second)
	if src1.String() == src2.String() {
		t.Fatalf("both sessions share one egress socket (%s) — per-session egress broken", src1)
	}

	// Replies must be routed back per session: "reply-A" only to client 1,
	// "reply-B" only to client 2.
	if _, err := fakeWG.WriteToUDP([]byte("reply-A"), src1); err != nil {
		t.Fatalf("reply A: %v", err)
	}
	if _, err := fakeWG.WriteToUDP([]byte("reply-B"), src2); err != nil {
		t.Fatalf("reply B: %v", err)
	}
	expectUDP(t, wgClient1, "reply-A", 3*time.Second)
	expectUDP(t, wgClient2, "reply-B", 3*time.Second)

	// No cross-talk: client 1 must never see client 2's reply.
	_ = wgClient1.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
	buf := make([]byte, 65535)
	if n, _, err := wgClient1.ReadFromUDP(buf); err == nil && string(buf[:n]) == "reply-B" {
		t.Fatalf("client 1 received client 2's reply — session isolation broken")
	}
}

// TestMTUValidationRejectsOversizedInnerMTU proves the P2 guard: with FEC
// on, an inner MTU whose largest parity frame would exceed the 1500-byte
// path MTU is rejected at construction with the exact bound.
func TestMTUValidationRejectsOversizedInnerMTU(t *testing.T) {
	fecOn := &config.FEC{Enabled: true, Mode: config.FECAdaptive, MaxLossPct: 20}
	base := func(mtu int) *config.Config {
		return &config.Config{
			Mode:   config.ModeClient,
			Listen: "127.0.0.1:0",
			Server: "127.0.0.1:9",
			MTU:    mtu,
			FEC:    *fecOn,
			Crypto: config.Crypto{Key: "psk", Cipher: "chacha20poly1305"},
			WANs:   []config.WAN{{ID: "w1", Transport: config.TransportUDP, CapacityMbps: 100}},
		}
	}
	if _, err := NewClient(base(1420), testLogger()); err == nil {
		t.Fatal("MTU 1420 with FEC must be rejected (parity frames exceed path MTU)")
	}
	if _, err := NewClient(base(1390), testLogger()); err != nil {
		t.Fatalf("MTU 1390 with FEC must be accepted: %v", err)
	}
}

// startMultiWAN spins up a server + N-WAN client pair. Every client WAN
// transport is wrapped in a killable lossyTransport (returned) so tests can
// simulate a dead uplink.
func startMultiWAN(t *testing.T, psk string, nWans int, healthCfg config.Health) (srv *Server, cli *Client, fakeWG, wgClient *net.UDPConn, killable []*lossyTransport) {
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
		Health: healthCfg,
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
		Health: healthCfg,
		Scheduler: config.Sched{
			Mode:      config.SchedulerLB,
			BalanceBy: config.BalanceByCapacity,
			Affinity:  config.AffinityPacket,
		},
	}
	for i := 1; i <= nWans; i++ {
		cliCfg.WANs = append(cliCfg.WANs, config.WAN{
			ID: fmt.Sprintf("w%d", i), Transport: config.TransportUDP, CapacityMbps: 100,
		})
	}
	cli, err = NewClient(cliCfg, log)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	for _, wan := range cli.wans {
		kw := &lossyTransport{}
		kw.inner = wan.tr
		wan.tr = kw
		killable = append(killable, kw)
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
	return srv, cli, fakeWG, wgClient, killable
}

// TestMultiWANLoadBalances verifies that with two WANs of equal capacity the
// client scheduler spreads traffic over both (packet affinity), and every
// inner datagram still reaches the WG peer.
func TestMultiWANLoadBalances(t *testing.T) {
	srv, cli, fakeWG, wgClient, killable := startMultiWAN(t, "mwan-psk", 2, config.Health{})
	waitFor(t, "server session", func() bool { return srv.mgr.Count() == 1 }, 3*time.Second)

	// Warm-up round trip so the tunnel is fully established.
	sendUntilReceived(t, wgClient, cli.LocalAddr(), fakeWG, []byte("warmup"), 6*time.Second)

	// Burst: keep resending each unique ping until all 60 arrive (UDP is
	// lossy; the counters below reflect the scheduler's picks regardless).
	const n = 60
	sent := make(map[string]bool)
	got := make(map[string]bool)
	buf := make([]byte, 65535)
	deadline := time.Now().Add(8 * time.Second)
	for len(got) < n && time.Now().Before(deadline) {
		for i := 0; i < n; i++ {
			p := fmt.Sprintf("p%02d", i)
			if !got[p] && !sent[p] {
				if _, err := wgClient.WriteToUDP([]byte(p), cli.LocalAddr()); err == nil {
					sent[p] = true
				}
			}
		}
		_ = fakeWG.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		if nn, _, err := fakeWG.ReadFromUDP(buf); err == nil {
			got[string(buf[:nn])] = true
		}
	}
	if len(got) != n {
		t.Fatalf("only %d/%d pings arrived", len(got), n)
	}
	s0, s1 := killable[0].sends.Load(), killable[1].sends.Load()
	if s0 == 0 || s1 == 0 {
		t.Fatalf("one WAN carried no traffic: w1=%d w2=%d", s0, s1)
	}
	total := s0 + s1
	for i, kw := range killable {
		if share := float64(kw.sends.Load()) / float64(total); share < 0.2 {
			t.Fatalf("wan%d share %.0f%% — load balancing broken", i+1, share*100)
		}
	}
}

// TestMultiWANFailover verifies the circuit breaker end-to-end: killing one
// WAN must (a) keep traffic flowing on the survivor, (b) remove the dead WAN
// from rotation once its health trips, and (c) restore it after recovery.
func TestMultiWANFailover(t *testing.T) {
	// Probe every 100ms; degrade after 0.3s of non-compensable loss;
	// restore a revived path after 3s of stability (recover_min is in
	// minutes, so 0.05 ≈ 3s).
	hc := config.Health{ProbeInterval: 0.1, DegradeSec: 0.3, RecoverMin: 0.05}
	srv, cli, fakeWG, wgClient, killable := startMultiWAN(t, "failover-psk", 2, hc)
	waitFor(t, "server session", func() bool { return srv.mgr.Count() == 1 }, 3*time.Second)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Pinger: keeps inner traffic flowing for the whole test.
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := wgClient.WriteToUDP([]byte("ping"), cli.LocalAddr()); err != nil {
					return
				}
			}
		}
	}()
	// Collector: counts arrivals at the WG peer.
	var arrived atomic.Int64
	go func() {
		buf := make([]byte, 65535)
		for {
			_ = fakeWG.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
			if _, _, err := fakeWG.ReadFromUDP(buf); err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			arrived.Add(1)
		}
	}()

	// (0) both WANs must be carrying data before the kill.
	waitFor(t, "both WANs in use", func() bool {
		return cli.byWAN["w1"].framesSent.Load() > 5 && cli.byWAN["w2"].framesSent.Load() > 5
	}, 8*time.Second)

	// (1) kill WAN2: arrivals must continue in every 500ms window (the
	// surviving WAN carries on).
	killable[1].killAll.Store(true)
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		before := arrived.Load()
		time.Sleep(500 * time.Millisecond)
		if arrived.Load() == before {
			t.Fatal("no traffic arrived after WAN2 died")
		}
	}

	// (2) the breaker trips: WAN2 goes DOWN and leaves rotation (its data
	// frame counter freezes; keepalive probes still flow, by design).
	waitFor(t, "wan2 DOWN", func() bool { return cli.byWAN["w2"].health.State() == health.StateDown }, 5*time.Second)
	frozen := cli.byWAN["w2"].framesSent.Load()
	time.Sleep(1200 * time.Millisecond)
	if cli.byWAN["w2"].framesSent.Load() != frozen {
		t.Fatalf("wan2 still scheduled after DOWN (frames %d → %d)", frozen, cli.byWAN["w2"].framesSent.Load())
	}

	// (3) revive: after the stability window the path returns to rotation.
	killable[1].killAll.Store(false)
	waitFor(t, "wan2 restored", func() bool { return cli.byWAN["w2"].framesSent.Load() > frozen }, 30*time.Second)
}

// TestParityFrameFitsPathMTU pins the P2 MTU math: the largest frame on the
// wire (a parity frame with a max-size payload) must fit the path MTU
// without IP fragmentation.
func TestParityFrameFitsPathMTU(t *testing.T) {
	const pathMTU = 1500
	const k = 10
	wire := func(innerMTU int) int {
		return innerMTU + frame.HeaderSize + frame.TagSize + fec.ParityHeaderSize(k)
	}
	if got := wire(1390); got > pathMTU {
		t.Fatalf("parity frame %dB exceeds path MTU %dB", got, pathMTU)
	}
	if got := wire(1420); got <= pathMTU {
		t.Fatalf("expected parity frame at MTU 1420 to exceed path MTU, got %dB", got)
	}
}
