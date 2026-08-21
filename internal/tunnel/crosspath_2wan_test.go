package tunnel

// Regression: a client configured with NO FEC adopts server cross-path FEC
// over TWO WANs. Cross-path blocks span every WAN, so this is the only
// topology where the adoption actually exercises the shared codec across
// paths. The earlier test used a single WAN (everything on one path, so a
// stale per-WAN decoder still happened to deliver in-order) and missed it.
// See the VPS matrix run: server announced crosspath, client stayed on its
// per-WAN (pass-through) decoder -> 100% loss on a clean link.

import (
	"context"
	"testing"
	"time"

	"github.com/ColinFL/flexbraid/internal/config"
)

func TestClientAdoptsServerCrosspathTwoWAN(t *testing.T) {
	log := testLogger()
	fakeWG := mustListenUDP(t)

	srvCfg := &config.Config{
		Mode:   config.ModeServer,
		Listen: "127.0.0.1:0",
		WGPeer: fakeWG.LocalAddr().String(),
		FEC: config.FEC{
			Enabled: true, Mode: config.FECCrosspath,
			DataShards: 10, ProtectionLevel: 0.5, BlockTimeoutMS: 8,
		},
		MTU:    1388,
		Crypto: config.Crypto{Key: "psk", Cipher: "chacha20poly1305"},
	}
	srv, err := NewServer(srvCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = srv.Run(ctx) }()

	// Client has NO fec/ — exactly the production field setup.
	cliCfg := &config.Config{
		Mode:   config.ModeClient,
		Listen: "127.0.0.1:0",
		Server: srv.LocalAddr().String(),
		Crypto: config.Crypto{Key: "psk", Cipher: "chacha20poly1305"},
		WANs: []config.WAN{
			{ID: "w1", Transport: config.TransportUDP, CapacityMbps: 100},
			{ID: "w2", Transport: config.TransportUDP, CapacityMbps: 100},
		},
	}
	cli, err := NewClient(cliCfg, log)
	if err != nil {
		t.Fatal(err)
	}
	if err := cli.Start(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = cli.Run(ctx) }()

	wgClient := mustListenUDP(t)

	waitFor(t, "cross-path session over two WANs", func() bool {
		if _, ready := cli.getSessionAEAD(); !ready {
			return false
		}
		cli.codecMu.RLock()
		defer cli.codecMu.RUnlock()
		if !cli.crossPath || cli.xdec == nil {
			return false
		}
		// THE regression: every WAN's recv codec must be the shared
		// cross-path decoder, or blocks spread over both WANs never
		// reassemble.
		for _, wan := range cli.wans {
			if wan.dec != cli.xdec || wan.enc != cli.xenc {
				return false
			}
		}
		return true
	}, 5*time.Second)

	sendUntilReceived(t, wgClient, mustUDPAddr(t, cli.ingress.LocalAddr().String()), fakeWG,
		[]byte("crosspath-2wan-ok"), 5*time.Second)
}
