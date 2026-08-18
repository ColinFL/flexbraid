//go:build linux || freebsd

package transport

import (
	"errors"
	"fmt"
	"math/rand"
	"net"

	"golang.org/x/sys/unix"
)

// openRawSocket creates the raw IPv4/TCP socket used for both directions.
// IP_HDRINCL makes the kernel pass our prebuilt IP header through
// untouched (and deliver received datagrams with their IP header, which is
// what raw sockets do anyway).
// errRawPerm marks raw-socket permission failures so tests can skip
// cleanly on unprivileged runners.
var errRawPerm = errors.New("raw socket permission denied (requires root/CAP_NET_RAW)")

func openRawSocket(id string, bind Bind) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_TCP)
	if err != nil {
		if errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES) {
			return -1, errRawPerm
		}
		return -1, fmt.Errorf(
			"faketcp[%s]: raw socket: %w (faketcp requires root/CAP_NET_RAW and RST suppression; see docs/CONFIG.md)", id, err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("faketcp[%s]: IP_HDRINCL: %w", id, err)
	}
	if err := bindToRaw(fd, bind); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("faketcp[%s]: %w", id, err)
	}
	return fd, nil
}

// bindToRaw pins the raw socket to the WAN: device binding (SO_BINDTODEVICE
// on Linux) or a source-address bind (local_ip). Same semantics as the UDP
// transport (bind.go), applied to a raw fd.
func bindToRaw(fd int, bind Bind) error {
	if bind.Iface != "" {
		err := setDeviceBinding(fd, bind.Iface)
		if err == nil {
			return nil
		}
		// Permission/unsupported errors fall back to local_ip when one is
		// configured (identical to the UDP transport's fallback).
		if bind.LocalIP != "" && (errors.Is(err, ErrDeviceBindUnsupported) ||
			errors.Is(err, unix.EPERM) || errors.Is(err, unix.EACCES)) {
			return bindLocalIP(fd, bind.LocalIP)
		}
		return fmt.Errorf("bind to device %q: %w", bind.Iface, err)
	}
	if bind.LocalIP != "" {
		return bindLocalIP(fd, bind.LocalIP)
	}
	return nil
}

func bindLocalIP(fd int, localIP string) error {
	ip := net.ParseIP(localIP).To4()
	if ip == nil {
		return fmt.Errorf("bind local_ip %q is not a valid IPv4 address", localIP)
	}
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], ip)
	if err := unix.Bind(fd, &sa); err != nil {
		return fmt.Errorf("bind to %s: %w", localIP, err)
	}
	return nil
}

func closeRawSocket(fd int) error {
	return unix.Close(fd)
}

func writeRaw(fd int, seg []byte, _ net.IP) (int, error) {
	// IP_HDRINCL: the segment already contains the IP header; the kernel
	// only needs the destination (the header's dst field must match).
	dst := net.IP(seg[16:20]).To4()
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], dst)
	if err := unix.Sendto(fd, seg, 0, &sa); err != nil {
		return 0, err
	}
	return len(seg), nil
}

func readRaw(fd int, buf []byte) (int, error) {
	return unix.Read(fd, buf)
}

// localIPFor returns the local source IP the kernel would use to reach dst
// (routing-table probe: a connected UDP socket picks the source address
// without sending anything).
func (f *FakeTCP) localIPFor(dst net.IP) net.IP {
	key := dst.String()
	f.srcMu.Lock()
	if ip, ok := f.srcFor[key]; ok {
		f.srcMu.Unlock()
		return ip
	}
	f.srcMu.Unlock()

	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: dst, Port: 9})
	if err != nil {
		return net.IPv4zero
	}
	defer conn.Close()
	if la, ok := conn.LocalAddr().(*net.UDPAddr); ok && la.IP.To4() != nil {
		ip := la.IP.To4()
		f.srcMu.Lock()
		f.srcFor[key] = ip
		f.srcMu.Unlock()
		return ip
	}
	return net.IPv4zero
}

func randUint32() uint32 { return rand.Uint32() }
