package transport

import (
	"bytes"
	"net"
	"testing"
)

// TestBuildParseRoundtrip verifies a built segment parses back with the
// same addressing, flags, seq and payload, and a valid TCP checksum.
func TestBuildParseRoundtrip(t *testing.T) {
	src := net.ParseIP("192.0.2.10").To4()
	dst := net.ParseIP("198.51.100.1").To4()
	payload := []byte("hello faketcp")
	seg := buildSegment(src, dst, 12345, 44, 0x11223344, 0x55667788, tcpFlagPSH|tcpFlagACK, payload)

	got, addr, dstPort, syn, seq, ok := parseSegment(seg)
	if !ok {
		t.Fatal("segment did not parse")
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %q", got)
	}
	if addr.String() != "192.0.2.10:12345" {
		t.Fatalf("source mismatch: %v", addr)
	}
	if dstPort != 44 {
		t.Fatalf("dst port mismatch: %d", dstPort)
	}
	if syn {
		t.Fatal("unexpected SYN flag")
	}
	if seq != 0x11223344 {
		t.Fatalf("seq mismatch: %#x", seq)
	}
	if !validTCPChecksum(src, dst, seg[ipHdrLen:]) {
		t.Fatal("TCP checksum invalid")
	}
	if ipChecksum(seg[:ipHdrLen]) != 0 {
		t.Fatal("IP checksum invalid")
	}
}

// TestParseRejectsBadSegments: RST/FIN, fragmented datagrams and wrong
// protocol must all be refused by the parser.
func TestParseRejectsBadSegments(t *testing.T) {
	src := net.ParseIP("10.0.0.1").To4()
	dst := net.ParseIP("10.0.0.2").To4()
	base := func() []byte {
		return buildSegment(src, dst, 1000, 44, 1, 1, tcpFlagACK, []byte("x"))
	}
	// RST must be ignored (kernel/nat noise).
	rst := base()
	rst[ipHdrLen+13] = tcpFlagRST
	if _, _, _, _, _, ok := parseSegment(rst); ok {
		t.Fatal("RST segment must be rejected")
	}
	// FIN likewise.
	fin := base()
	fin[ipHdrLen+13] = tcpFlagFIN
	if _, _, _, _, _, ok := parseSegment(fin); ok {
		t.Fatal("FIN segment must be rejected")
	}
	// Fragmented (offset != 0) must be rejected.
	frag := base()
	frag[6], frag[7] = 0x00, 0x40 // frag offset 4
	if _, _, _, _, _, ok := parseSegment(frag); ok {
		t.Fatal("fragmented segment must be rejected")
	}
	// Non-TCP protocol must be rejected.
	icmp := base()
	icmp[9] = 1
	if _, _, _, _, _, ok := parseSegment(icmp); ok {
		t.Fatal("non-TCP segment must be rejected")
	}
	// Corrupted TCP checksum must be rejected.
	bad := base()
	bad[ipHdrLen+16] ^= 0xff
	if _, _, _, _, _, ok := parseSegment(bad); ok {
		t.Fatal("segment with corrupt checksum must be rejected")
	}
}

// TestFakeHandshakeSequence simulates the 0-RTT fake 3-way handshake with
// data on the first segment: client SYN+data → server SYN|ACK+data →
// client ACK. Seq/ack must walk like a real TCP conversation.
func TestFakeHandshakeSequence(t *testing.T) {
	cliIP := net.ParseIP("192.0.2.10").To4()
	srvIP := net.ParseIP("198.51.100.1").To4()
	const cliPort, srvPort = 12345, 44

	// Client's first send: SYN + FIRST payload.
	cliState := &peerState{mySeq: 1000}
	seg := buildSegment(cliIP, srvIP, cliPort, srvPort, cliState.mySeq, 0, tcpFlagSYN, []byte("first"))
	cliState.mySeq += seqAdvance(len("first"))

	// Server receives it.
	payload, addr, dstPort, syn, seq, ok := parseSegment(seg)
	if !ok {
		t.Fatal("client SYN+data did not parse")
	}
	if syn != true || string(payload) != "first" {
		t.Fatalf("server saw syn=%v payload=%q", syn, payload)
	}
	if dstPort != srvPort || addr.Port != cliPort {
		t.Fatalf("server saw %v:%d", addr, dstPort)
	}
	srvPeer := &peerState{mySeq: 5000}
	srvPeer.peerSeq = seq + 1 // SYN consumes one seq

	// Server replies SYN|ACK + response data.
	reply := buildSegment(srvIP, cliIP, srvPort, cliPort, srvPeer.mySeq, srvPeer.peerSeq, tcpFlagSYN|tcpFlagACK, []byte("pong"))
	srvPeer.mySeq += seqAdvance(len("pong"))

	// Client receives the reply.
	payload2, _, _, syn2, seq2, ok := parseSegment(reply)
	if !ok {
		t.Fatal("server SYN|ACK did not parse")
	}
	if syn2 != true || string(payload2) != "pong" {
		t.Fatalf("client saw syn=%v payload=%q", syn2, payload2)
	}
	cliPeer := &peerState{mySeq: cliState.mySeq}
	cliPeer.peerSeq = seq2 + 1

	// Client's next segment must be PSH|ACK with ack == server seq.
	next := buildSegment(cliIP, srvIP, cliPort, srvPort, cliPeer.mySeq, cliPeer.peerSeq, tcpFlagPSH|tcpFlagACK, []byte("more"))
	if got := next[ipHdrLen+13]; got != tcpFlagPSH|tcpFlagACK {
		t.Fatalf("client ACK flags = %#x", got)
	}
	ack := uint32(next[ipHdrLen+8])<<24 | uint32(next[ipHdrLen+9])<<16 | uint32(next[ipHdrLen+10])<<8 | uint32(next[ipHdrLen+11])
	if ack != 5001 { // server seq + 1 (SYN)
		t.Fatalf("client ack = %d, want 5001", ack)
	}
}

// TestLocalAddrBeforeAndAfterOpen guards the LocalAddr contract: nil-unsafe
// access must not panic before Open.
func TestLocalAddrNotPanic(t *testing.T) {
	f := NewFakeTCP("w1", "0.0.0.0:4096", "", Bind{})
	_ = f.LocalAddr() // must not panic
	_ = f.Close()
}
