//go:build freebsd

package transport

import (
	"fmt"
	"net"

	"golang.org/x/sys/unix"
)

// ipBoundIf is IP_BOUND_IF from <netinet/in.h> (FreeBSD ≥ 12): bind a UDP
// socket to a particular interface by index. It is not exported by
// x/sys/unix for freebsd (only darwin/solaris), so it is defined here.
const ipBoundIf = 53

// setDeviceBinding pins the socket to a device via IP_BOUND_IF, which
// requires the interface index.
func setDeviceBinding(fd int, iface string) error {
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %q: %w", iface, err)
	}
	return unix.SetsockoptInt(fd, unix.IPPROTO_IP, ipBoundIf, ifi.Index)
}
