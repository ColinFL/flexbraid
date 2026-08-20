package tunnel

// Tests for server-authoritative parameters (config.ServerAnnounce): the
// client must adopt the server's FEC geometry + inner MTU from the KEX_ACK
// and rebuild its codecs before the session key is published — so a client
// config no longer needs to (and should not) duplicate them.

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/ColinFL/flexbraid/internal/config"
)

// mustListenUDP opens a loopback UDP socket for the fake WG peer.
func mustListenUDP(t *testing.T) *net.UDPConn {
	t.Helper()
	c, err := net.ListenUDP("udp", mustUDPAddr(t, "127.0.0.1:0"))
	if err != nil {
		t.Fatalf("udp listen: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// startPairServerFEC starts a real pair where the SERVER configures FEC but
// the CLIENT config has none (the simplified setup the announce feature
// exists for). Returns the same tuple as startTestPair.
func startPairServerFEC(t *testing.T, fecCfg *config.FEC) (*Server, *Client, *net.UDPConn, *net.UDPConn) {
	t.Helper()
	log := testLogger()

	fakeWG := mustListenUDP(t)
	srvCfg := &config.Config{
		Mode:   config.ModeServer,
		Listen: "127.0.0.1:0",
		WGPeer: fakeWG.LocalAddr().String(),
		FEC:    *fecCfg,
		MTU:    1388, // largest parity frame must fit a 1500-byte path (P2)
		Crypto: config.Crypto{Key: "psk", Cipher: "chacha20poly1305"},
	}
	srv, err := NewServer(srvCfg, log)
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("server start: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Run(ctx) }()

	// Client deliberately carries NO fec/ and NO mtu/ — the server's values
	// must arrive via the KEX_ACK.
	cliCfg := &config.Config{
		Mode:   config.ModeClient,
		Listen: "127.0.0.1:0",
		Server: srv.LocalAddr().String(),
		Crypto: config.Crypto{Key: "psk", Cipher: "chacha20poly1305"},
		WANs: []config.WAN{{
			ID: "w1", Transport: config.TransportUDP, CapacityMbps: 100,
		}},
	}
	cli, err := NewClient(cliCfg, log)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	if err := cli.Start(); err != nil {
		t.Fatalf("client start: %v", err)
	}
	go func() { _ = cli.Run(ctx) }()

	wgClient := mustListenUDP(t)
	return srv, cli, fakeWG, wgClient
}

// TestClientAdoptsServerFEC: a client configured with NO FEC adopts the
// server's geometry from the KEX_ACK — codecs become enabled with the
// server's data_shards and effective MTU, and data traverses end-to-end.
func TestClientAdoptsServerFEC(t *testing.T) {
	_, cli, fakeWG, wgClient := startPairServerFEC(t, &config.FEC{
		Enabled:          true,
		Mode:             config.FECFixed,
		DataShards:       10,
		FixedOverheadPct: 25, // → 3 parity shards; forces coding on
	})

	waitFor(t, "PFS session + server parameters adopted", func() bool {
		if _, ready := cli.getSessionAEAD(); !ready {
			return false
		}
		cli.codecMu.RLock()
		defer cli.codecMu.RUnlock()
		return cli.wans[0].enc.Params().Enabled()
	}, 5*time.Second)

	cli.codecMu.RLock()
	p := cli.wans[0].enc.Params()
	mtu := cli.mtu.Load()
	crossPath := cli.crossPath
	cli.codecMu.RUnlock()
	if !p.Enabled() {
		t.Fatal("client codecs did not adopt the server's enabled FEC")
	}
	if p.DataShards != 10 {
		t.Fatalf("client adopted wrong data_shards: got %d, want 10 ", p.DataShards)
	}
	if mtu != 1388 {
		t.Fatalf("client did not adopt server MTU: got %d, want 1388", mtu)
	}
	if crossPath {
		t.Fatal("per-WAN mode adopted as cross-path")
	}
	sendUntilReceived(t, wgClient, mustUDPAddr(t, cli.ingress.LocalAddr().String()), fakeWG,
		[]byte("adopted-fec-ok"), 5*time.Second)
}

// TestClientAdoptsServerCrosspath: a server announcing fec.mode=crosspath
// switches the FEC-less client onto the shared cross-path codec, and data
// still flows.
func TestClientAdoptsServerCrosspath(t *testing.T) {
	_, cli, fakeWG, wgClient := startPairServerFEC(t, &config.FEC{
		Enabled:         true,
		Mode:            config.FECCrosspath,
		DataShards:      10,
		ProtectionLevel: 0.5,
	})

	waitFor(t, "cross-path session established", func() bool {
		if _, ready := cli.getSessionAEAD(); !ready {
			return false
		}
		cli.codecMu.RLock()
		defer cli.codecMu.RUnlock()
		return cli.crossPath && cli.xenc != nil && cli.xdec != nil
	}, 5*time.Second)

	cli.codecMu.RLock()
	crossPath, xenc := cli.crossPath, cli.xenc
	cli.codecMu.RUnlock()
	if !crossPath || xenc == nil {
		t.Fatal("client did not adopt server's cross-path FEC")
	}
	if p := xenc.Params(); p.DataShards != 10 {
		t.Fatalf("cross-path data_shards: got %d, want 10", p.DataShards)
	}
	if mtu := cli.mtu.Load(); mtu != 1388 {
		t.Fatalf("cross-path MTU: got %d, want 1388", mtu)
	}
	sendUntilReceived(t, wgClient, mustUDPAddr(t, cli.ingress.LocalAddr().String()), fakeWG,
		[]byte("adopted-crosspath-ok"), 5*time.Second)
}

// TestApplyAnnounceRejectsBadVersion: a mismatch on the wire schema version
// must abort the handshake (never guess at field meanings), and a missing
// block tells the operator the server is too old.
func TestApplyAnnounceRejectsBadVersion(t *testing.T) {
	cli, err := NewClient(&config.Config{
		Mode:   config.ModeClient,
		Listen: "127.0.0.1:0",
		Server: "127.0.0.1:1",
		Crypto: config.Crypto{Key: "psk", Cipher: "chacha20poly1305"},
		WANs: []config.WAN{{
			ID: "w1", Transport: config.TransportUDP, CapacityMbps: 100,
		}},
	}, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.applyAnnounce(nil); err == nil {
		t.Fatal("empty announce should be rejected (old server)")
	}
	bad, _ := json.Marshal(config.ServerAnnounce{Version: 99})
	if err := cli.applyAnnounce(bad); err == nil {
		t.Fatal("unknown announce version should be rejected")
	}
	// A valid announce must be accepted (geometry: no FEC).
	ok, _ := json.Marshal(config.ServerAnnounce{
		Version: config.AnnounceVersion,
		MTU:     1420,
		FEC:     config.FEC{},
	})
	if err := cli.applyAnnounce(ok); err != nil {
		t.Fatalf("valid announce rejected: %v", err)
	}
	if cli.crossPath {
		t.Fatal("FEC-less server announced cross-path")
	}
}

// TestServerAnnounceRoundTrip: what the server marshals is exactly what the
// client decodes (the single source of truth must survive the wire).
func TestServerAnnounceRoundTrip(t *testing.T) {
	want := config.ServerAnnounce{
		Version: config.AnnounceVersion,
		MTU:     1388,
		FEC:     config.FEC{Enabled: true, Mode: config.FECAdaptive, DataShards: 10},
	}
	data, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	var got config.ServerAnnounce
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	// Compare the FEC geometry that actually reaches fecParamsFor.
	if got.Version != want.Version || got.MTU != want.MTU ||
		got.FEC.Enabled != want.FEC.Enabled || got.FEC.Mode != want.FEC.Mode ||
		got.FEC.DataShards != want.FEC.DataShards {
		t.Fatalf("announce round trip mismatch:\n got %+v\nwant %+v", got, want)
	}
}
