//go:build linux || freebsd

package transport

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// openICMPSocket creates the raw ICMP socket used for both directions.
// Unlike FakeTCP, no IP_HDRINCL is needed: the kernel builds the IP header
// for echo packets; received datagrams arrive with their IP header (as raw
// sockets always deliver).
func openICMPSocket(id string, bind Bind) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP)
	if err != nil {
		if errorsIsPerm(err) {
			return -1, errRawPerm
		}
		return -1, fmt.Errorf(
			"icmp[%s]: raw socket: %w (icmp requires root/CAP_NET_RAW; see docs/CONFIG.md)", id, err)
	}
	if err := bindToRaw(fd, bind); err != nil {
		unix.Close(fd)
		return -1, fmt.Errorf("icmp[%s]: %w", id, err)
	}
	return fd, nil
}

func errorsIsPerm(err error) bool {
	return err == unix.EPERM || err == unix.EACCES
}

// sendICMP sends one prebuilt echo packet to dst (IP header built by the
// kernel; source chosen by routing, or the bind's local_ip).
func sendICMP(fd int, pkt []byte, dst net.IP) error {
	var sa unix.SockaddrInet4
	copy(sa.Addr[:], dst.To4())
	return unix.Sendto(fd, pkt, 0, &sa)
}
