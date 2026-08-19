package transport

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

// TestEchoRoundtrip: a built echo request parses back with the right
// payload/id/type; the checksum validity is reported separately. A request
// built with corruptCS must parse with csOK=false (that is the flexbraid
// client marker), while corrupting the payload flips csOK to false too.
func TestEchoRoundtrip(t *testing.T) {
	src := net.ParseIP("192.0.2.10").To4()
	dst := net.ParseIP("198.51.100.1").To4()
	payload := []byte("ping data")
	pkt := buildEcho(icmpTypeEchoRequest, 0x1234, 7, payload, false)

	// Wrap in an IP header like the raw socket delivers.
	ip := buildIPWrap(src, dst, pkt)

	got, addr, rtype, id, csOK, ok := parseEcho(ip)
	if !ok {
		t.Fatal("echo packet did not parse")
	}
	if !csOK {
		t.Fatal("well-formed echo must have a valid checksum")
	}
	if rtype != icmpTypeEchoRequest || id != 0x1234 {
		t.Fatalf("type=%d id=%#x", rtype, id)
	}
	if addr.IP.String() != "192.0.2.10" {
		t.Fatalf("source mismatch: %v", addr)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: %q", got)
	}

	// Corrupt payload → checksum reports invalid.
	bad := buildEcho(icmpTypeEchoRequest, 0x1234, 7, payload, false)
	bad[icmpHdrLen] ^= 0xff
	if _, _, _, _, csOK, ok := parseEcho(buildIPWrap(src, dst, bad)); !ok || csOK {
		t.Fatal("corrupt payload must parse but report csOK=false")
	}

	// corruptCS marker: parses, but the checksum is invalid — exactly what
	// the server matches on (and the kernel refuses to answer).
	marker := buildEcho(icmpTypeEchoRequest, 0x1234, 7, payload, true)
	if _, _, _, _, csOK, ok := parseEcho(buildIPWrap(src, dst, marker)); !ok || csOK {
		t.Fatal("corrupt-checksum marker must parse but report csOK=false")
	}
}

// buildIPWrap wraps an ICMP packet in a minimal IPv4 header, mimicking a
// raw socket's receive image.
func buildIPWrap(src, dst net.IP, icmp []byte) []byte {
	total := ipHdrLen + len(icmp)
	b := make([]byte, total)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(total))
	b[9] = 1 // ICMP
	copy(b[12:16], src.To4())
	copy(b[16:20], dst.To4())
	copy(b[ipHdrLen:], icmp)
	return b
}

// TestEchoFilters: non-echo ICMP types and wrong identifiers are rejected.
func TestEchoFilters(t *testing.T) {
	src := net.ParseIP("10.0.0.1").To4()
	dst := net.ParseIP("10.0.0.2").To4()
	// Destination unreachable (type 3) must be ignored.
	dup := buildEcho(icmpTypeEchoRequest, 1, 1, []byte("x"), false)
	dup[0] = 3
	if _, _, rtype, _, _, ok := parseEcho(buildIPWrap(src, dst, dup)); ok {
		t.Fatalf("non-echo ICMP (type %d) must be rejected", rtype)
	}
	// Wrong protocol (TCP) must be rejected.
	tcpPkt := buildIPWrap(src, dst, dup)
	tcpPkt[9] = 6
	if _, _, _, _, _, ok := parseEcho(tcpPkt); ok {
		t.Fatal("non-ICMP datagram must be rejected")
	}
	// Fragmented must be rejected.
	frag := buildIPWrap(src, dst, buildEcho(icmpTypeEchoRequest, 1, 1, []byte("x"), false))
	frag[6], frag[7] = 0x00, 0x40
	if _, _, _, _, _, ok := parseEcho(frag); ok {
		t.Fatal("fragmented datagram must be rejected")
	}
}
