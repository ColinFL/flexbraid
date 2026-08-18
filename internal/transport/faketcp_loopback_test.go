//go:build linux

package transport

import (
	"bytes"
	"errors"
	"net"
	"testing"
	"time"
)

// TestFakeTCPLoopback runs a full client↔server exchange over the loopback
// interface with real raw sockets: SYN+data → SYN|ACK+data → PSH|ACK, then
// several data round trips. Requires root/CAP_NET_RAW — skipped otherwise
// (GitHub runners run unprivileged).
func TestFakeTCPLoopback(t *testing.T) {
	const srvPort = 39999

	cli := NewFakeTCP("w1", "127.0.0.1:0", "127.0.0.1:39999", Bind{})
	srv := NewFakeTCP("wan", "127.0.0.1:39999", "", Bind{})

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

	// Server recv loop.
	recvCh := make(chan []byte, 4)
	addrCh := make(chan net.Addr, 4)
	errCh := make(chan error, 1)
	go func() {
		for {
			b, addr, err := srv.Recv()
			if err != nil {
				errCh <- err
				return
			}
			recvCh <- b
			addrCh <- addr
		}
	}()

	// 1. Client sends FIRST (SYN + data) — 0-RTT fake handshake.
	if err := cli.Send([]byte("first")); err != nil {
		t.Fatalf("client send: %v", err)
	}
	var srvAddr net.Addr
	select {
	case b := <-recvCh:
		if string(b) != "first" {
			t.Fatalf("server got %q, want first", b)
		}
		srvAddr = <-addrCh
	case err := <-errCh:
		t.Fatalf("server recv: %v", err)
	case <-time.After(3 * time.Second):
		t.Fatal("server did not receive the first segment")
	}

	// 2. Server replies (SYN|ACK + data).
	if err := srv.SendTo(srvAddr, []byte("pong")); err != nil {
		t.Fatalf("server send: %v", err)
	}
	assertRecv := func(want string) {
		t.Helper()
		select {
		case b := <-recvCh:
			if string(b) != want {
				t.Fatalf("got %q, want %q", b, want)
			}
		case err := <-errCh:
			t.Fatalf("recv: %v", err)
		case <-time.After(3 * time.Second):
			t.Fatalf("did not receive %q", want)
		}
	}
	assertRecv("pong")

	// 3. Subsequent data round trips (PSH|ACK phase both ways).
	for i := 0; i < 5; i++ {
		msg := []byte{byte('a' + i), byte(i)}
		if err := cli.Send(msg); err != nil {
			t.Fatalf("client send %d: %v", i, err)
		}
		select {
		case b := <-recvCh:
			if !bytes.Equal(b, msg) {
				t.Fatalf("server got %v, want %v", b, msg)
			}
		case err := <-errCh:
			t.Fatalf("server recv %d: %v", i, err)
		case <-time.After(3 * time.Second):
			t.Fatalf("server missed round trip %d", i)
		}
		reply := []byte{0xff, byte(i)}
		if err := srv.SendTo(srvAddr, reply); err != nil {
			t.Fatalf("server send %d: %v", i, err)
		}
	}
	for i := 0; i < 5; i++ {
		assertRecv(string([]byte{0xff, byte(i)}))
	}
}
