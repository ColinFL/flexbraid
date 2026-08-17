//go:build freebsd

package transport

import "fmt"

// setDeviceBinding pins the socket to a device. IP_BOUND_IF existed on
// FreeBSD 12–14 but was removed in 15, so on modern OPNsense/FreeBSD this
// always fails. The caller falls back to source-address binding (local_ip)
// or fails with an actionable error (see UDP.dialBound).
func setDeviceBinding(fd int, iface string) error {
	return fmt.Errorf("%w (IP_BOUND_IF removed in FreeBSD 15; configure wan.local_ip with policy routing — pf route-to / setfib — to pin a socket to an uplink)", ErrDeviceBindUnsupported)
}
