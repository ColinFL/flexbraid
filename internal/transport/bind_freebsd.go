//go:build freebsd

package transport

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

// setDeviceBinding pins the socket to one uplink via its routing table
// (FIB). IP_BOUND_IF existed on FreeBSD 12–14 but was removed in 15;
// the supported mechanism on modern FreeBSD/OPNsense is SO_SETFIB, which
// requires net.fibs > 1 (loader.conf) and one default route per FIB.
func setDeviceBinding(fd int, iface string, fib int) error {
	if fib >= 0 {
		// SO_SETFIB: route this socket via the FIB's tables. Requires
		// net.fibs > 1 (loader.conf) and a default route per FIB.
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, unix.SO_SETFIB, fib); err != nil {
			return fmt.Errorf("setsockopt(SO_SETFIB, fib %d): %w", fib, err)
		}
		return nil
	}
	return fmt.Errorf("%w (FreeBSD 15 removed IP_BOUND_IF; set wan.fib (SO_SETFIB, needs net.fibs>1) or use local_ip with pf route-to)", ErrDeviceBindUnsupported)
}
