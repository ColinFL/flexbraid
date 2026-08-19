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
// request. Empty replies are legal (the server had nothing queued yet), so
// recvUntil skips them. Requires root/CAP_NET_RAW — skipped otherwise
// (CI runs it in a NET_RAW container).
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
	srvErrCh := make(chan error, 1)
	go func() {
		for {
			b, _, err := srv.Recv()
			if err != nil {
				srvErrCh <- err
				return
			}
			srvRecvCh <- b
		}
	}()
	cliRecvCh := make(chan []byte, 8)
	cliErrCh := make(chan error, 1)
	go func() {
		// Diagnose raw: read the client's fd directly and log EVERY
		// ICMP echo packet the client's socket sees, filtered or not.
		buf := make([]byte, 65535)
		for {
			n, err := readRaw(cli.fd, buf)
			if err != nil {
				cliErrCh <- err
				return
			}
			frame, src, rtype, id, csOK, ok := parseEcho(buf[:n])
			if !ok {
				t.Logf("  raw: unparsable (%d bytes)", n)
				continue
			}
			show := frame
			if len(show) > 24 {
				show = show[:24]
			}
			t.Logf("  raw: type=%d id=%d src=%s cs=%v payload=%q", rtype, id, src.IP, csOK, show)
			if rtype == icmpTypeEchoReply && csOK && id == cli.myID && src.IP.Equal(cli.clientDstIP) {
				// Copy: frame aliases the reused read buffer, which the
				// next readRaw overwrites (the exact bug this test once
				// masked by producing "queue" instead of "queued").
				out := make([]byte, len(frame))
				copy(out, frame)
				cliRecvCh <- out
			}
		}
	}()

	// recvUntil reads client frames until `want` arrives, skipping empty
	// replies (pull model: nothing queued) and logging everything seen.
	recvUntil := func(ch chan []byte, errCh chan error, want string) {
		t.Helper()
		deadline := time.After(3 * time.Second)
		for {
			select {
			case b := <-ch:
				t.Logf("  frame: %q (len %d)", b, len(b))
				if string(b) == want {
					return
				}
				if len(b) > 0 {
					t.Fatalf("got %q, want %q", b, want)
				}
			case err := <-errCh:
				t.Fatalf("recv: %v", err)
			case <-deadline:
				t.Fatalf("did not receive %q", want)
			}
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
	case err := <-srvErrCh:
		t.Fatalf("server recv: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive the first request")
	}

	// 2. Pull model: the server queues a reply BEFORE the next request;
	// the client's next ping must bring it back.
	srvPeer := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0}
	if err := srv.SendTo(srvPeer, []byte("queued")); err != nil {
		t.Fatalf("server queue: %v", err)
	}
	if err := cli.Send([]byte("ping2")); err != nil {
		t.Fatalf("client send 2: %v", err)
	}
	recvUntil(cliRecvCh, cliErrCh, "queued")
	// The "ping2" request that drained the queue is still travelling to
	// the server's recv goroutine; the reply already arrived, so the
	// request is buffered — consume it so it cannot pollute step 3.
	select {
	case b := <-srvRecvCh:
		if string(b) != "ping2" {
			t.Fatalf("server got %q, want ping2", b)
		}
	case err := <-srvErrCh:
		t.Fatalf("server recv: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("server never saw the ping2 request")
	}

	// 3. Steady-state round trips with data both ways. Each trip is:
	// client msg → server replies from queue → client tick 'k' drains the
	// next queued reply → the tick lands in the server's channel and must
	// be consumed before the next iteration (or it would be mistaken for
	// the next msg).
	for i := 0; i < 5; i++ {
		msg := []byte{byte('c' + i), byte(i)}
		if err := cli.Send(msg); err != nil {
			t.Fatalf("client send %d: %v", i, err)
		}
		select {
		case b := <-srvRecvCh:
			if string(b) != string(msg) {
				t.Fatalf("server got %q, want %q", b, msg)
			}
		case err := <-srvErrCh:
			t.Fatalf("server recv %d: %v", i, err)
		case <-time.After(3 * time.Second):
			t.Fatalf("server missed round trip %d", i)
		}
		reply := []byte{0xee, byte(i)}
		if err := srv.SendTo(srvPeer, reply); err != nil {
			t.Fatalf("server send %d: %v", i, err)
		}
		if err := cli.Send([]byte{'k'}); err != nil { // tick to drain the queue
			t.Fatalf("client tick %d: %v", i, err)
		}
		recvUntil(cliRecvCh, cliErrCh, string(reply))
		select {
		case b := <-srvRecvCh:
			if string(b) != "k" {
				t.Fatalf("server got %q, want tick 'k'", b)
			}
		case err := <-srvErrCh:
			t.Fatalf("server tick %d: %v", i, err)
		case <-time.After(3 * time.Second):
			t.Fatalf("server never saw tick %d", i)
		}
	}
}
