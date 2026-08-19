//go:build !linux && !freebsd

package transport

import (
	"errors"
	"math/rand"
	"net"
)

// errRawPerm is unavailable on this platform; Open always fails first.
var errRawPerm = errors.New("faketcp/icmp: raw sockets not supported on this platform")

// openRawSocket is unavailable on this platform (raw IPv4/TCP sockets
// need linux/freebsd).
func openRawSocket(id string, _ Bind) (int, error) {
	return -1, errRawPerm
}

// openICMPSocket is unavailable on this platform (raw ICMP sockets need
// linux/freebsd).
func openICMPSocket(id string, _ Bind) (int, error) {
	return -1, errRawPerm
}

func sendICMP(fd int, pkt []byte, dst net.IP) error { return errors.New("icmp: not open") }

func closeRawSocket(fd int) error { return errors.New("faketcp: not open") }

func writeRaw(fd int, seg []byte, _ net.IP) (int, error) {
	return 0, errors.New("faketcp: not open")
}

func readRaw(fd int, buf []byte) (int, error) { return 0, errors.New("faketcp: not open") }

// localIPFor falls back to unspecified (never used: Open fails first).
func (f *FakeTCP) localIPFor(dst net.IP) net.IP { return net.IPv4zero }

func randUint32() uint32 { return rand.Uint32() }
