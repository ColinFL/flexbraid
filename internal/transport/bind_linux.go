//go:build linux

package transport

import "golang.org/x/sys/unix"

// setDeviceBinding pins the socket to a device via SO_BINDTODEVICE. Only
// the root user / CAP_NET_RAW may set it; the caller treats EPERM/EACCES
// as the signal to fall back to local_ip binding.
func setDeviceBinding(fd int, iface string) error {
	return unix.SetsockoptString(fd, unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface)
}
