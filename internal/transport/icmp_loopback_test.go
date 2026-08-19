//go:build linux

package transport

import (
	"errors"
	"net"
	"testing"
	"time"
)

// TestICMPLoopback runs a full client↔server exchange over the loopback
// interface with real raw ICMP sockets, exercising the PULL model: the
// server's SendTo data is queued and drained by the client's next echo
// request. Requires root/CAP_NET_RAW — skipped otherwise (CI runs it in a
// NET_RAW container).
func TestICMPLoopback(t *testing.T) {
	const srvPort = 39998 // port ignored by icmp; kept for symmetry

	cli := NewICMP("w1", "127.0.0.1:0", "127.0.0.1:39998", Bind{})
	srv := NewICMP("wan", "127.0.0.1:39998", "", Bind{})

	if err := srv.Open(); err != nil {
		if errors.Is(err, errRawPerm) {
			t.Skipf("raw socket unavailable: %v", err)
		}
		t.Fatalf("server open: %v", err)
	}
	if err := cli.Open(); err != nil {
		t.Fatalf("client open: %v", err)
	}
	defer cli.Close()
	defer srv.Close()

	// Recv loops for both ends.
	srvRecvCh := make(chan []byte, 8)
	srvAddrCh := make(chan string, 8)
	srvErrCh := make(chan error, 1)
	go func() {
		for {
			b, addr, err := srv.Recv()
			if err != nil {
				srvErrCh <- err
				return
			}
			srvRecvCh <- b
			srvAddrCh <- addr.String()
		}
	}()
	cliRecvCh := make(chan []byte, 8)
	cliErrCh := make(chan error, 1)
	go func() {
		for {
			b, _, err := cli.Recv()
			if err != nil {
				cliErrCh <- err
				return
			}
			cliRecvCh <- b
		}
	}()

	recvFrom := func(ch chan []byte, errCh chan error, want string) {
		t.Helper()
		select {
		case b := <-ch:
			if string(b) != want {
				t.Fatalf("got %q, want %q", b, want)
			}
		case err := <-errCh:
			t.Fatalf("recv: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatalf("did not receive %q", want)
		}
	}

	// 1. Client → server: request carries data.
	if err := cli.Send([]byte("first")); err != nil {
		t.Fatalf("client send: %v", err)
	}
	select {
	case b := <-srvRecvCh:
		if string(b) != "first" {
			t.Fatalf("server got %q, want first", b)
		}
		srvAddr := <-srvAddrCh
		t.Logf("server saw peer %s", srvAddr)
	case err := <-srvErrCh:
		t.Fatalf("server recv: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive the first request")
	}

	// 2. Pull model: the server queues a reply BEFORE the next request;
	// the client's next ping must bring it back. Two pings: the first
	// drains the queue, the second is a clean round trip.
	srvPeer := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	if err := srv.SendTo(srvPeer, []byte("queued")); err != nil {
		t.Fatalf("server queue: %v", err)
	}
	if err := cli.Send([]byte("ping2")); err != nil {
		t.Fatalf("client send 2: %v", err)
	}
	recvFrom(cliRecvCh, cliErrCh, "queued")

	// 3. Steady-state round trips with data both ways.
	for i := 0; i < 5; i++ {
		msg := []byte{byte('c' + i), byte(i)}
		if err := cli.Send(msg); err != nil {
			t.Fatalf("client send %d: %v", i, err)
		}
		recvFrom(srvRecvCh, srvErrCh, string(msg))
		reply := []byte{0xee, byte(i)}
		if err := srv.SendTo(srvPeer, reply); err != nil {
			t.Fatalf("server send %d: %v", i, err)
		}
		if err := cli.Send([]byte{'k'}); err != nil { // tick to drain the queue
			t.Fatalf("client tick %d: %v", i, err)
		}
		recvFrom(cliRecvCh, cliErrCh, string(reply))
	}
}
