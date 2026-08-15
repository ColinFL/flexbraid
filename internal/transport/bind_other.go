//go:build !linux && !freebsd

package transport

import "fmt"

// setDeviceBinding is unsupported on this platform; configure local_ip
// instead.
func setDeviceBinding(fd int, iface string) error {
	return fmt.Errorf("iface binding is not supported on this platform; use local_ip")
}
