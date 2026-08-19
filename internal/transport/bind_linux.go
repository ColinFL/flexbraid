//go:build linux

package transport

import "golang.org/x/sys/unix"

// setDeviceBinding pins the socket to a device via SO_BINDTODEVICE. Only
// the root user / CAP_NET_RAW may set it; the caller treats EPERM/EACCES
// as the signal to fall back to local_ip binding. FIBs are FreeBSD-only
// and ignored here (Linux has one routing table).
func setDeviceBinding(fd int, iface string, fib int) error {
	if iface == "" {
		return nil // nothing to pin (fib-only configs are a FreeBSD pattern)
	}
	return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
}
