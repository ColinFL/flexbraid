//go:build !linux && !freebsd

package transport

import "fmt"

// setDeviceBinding is unsupported on this platform; configure local_ip
// instead. A fib-only config (FreeBSD pattern) is a no-op elsewhere.
func setDeviceBinding(fd int, iface string, fib int) error {
	if iface == "" {
		return nil
	}
	return fmt.Errorf("iface binding is not supported on this platform; use local_ip")
}
