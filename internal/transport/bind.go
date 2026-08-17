package transport

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// ErrDeviceBindUnsupported is returned when the platform cannot bind a
// socket to a device at all (e.g. FreeBSD 15 removed IP_BOUND_IF from the
// kernel). UDP.dialBound treats it like EPERM: fall back to local_ip when
// configured, otherwise fail with an actionable error.
var ErrDeviceBindUnsupported = errors.New("device binding is not supported on this platform")

// Bind pins a client WAN socket to one physical uplink. Without it the
// kernel routes every socket through the default route, and multi-WAN
// balancing silently collapses onto a single uplink.
//
// Two mechanisms, tried in order (see UDP.Open):
//   - Iface: bind the socket to a device — SO_BINDTODEVICE on Linux,
//     IP_BOUND_IF on FreeBSD. Requires CAP_NET_RAW / root; a daemon
//     running unprivileged gets EPERM.
//   - LocalIP: bind the source address instead (no privilege needed).
//     Requires the address to be assigned to the box and the OS routing
//     table to return traffic the same way (policy routing).
type Bind struct {
	Iface   string // device name (e.g. "igc1", "enp3s0")
	LocalIP string // source address (e.g. "192.0.2.10")
}

// Empty reports whether no binding was configured.
func (b Bind) Empty() bool { return b.Iface == "" && b.LocalIP == "" }

// bindToDevice attaches a raw socket fd to a network device. Platform
// specific: Linux uses SO_BINDTODEVICE, FreeBSD uses IP_BOUND_IF.
func bindToDevice(c syscall.RawConn, iface string) error {
	var err error
	if cerr := c.Control(func(fd uintptr) {
		err = setDeviceBinding(int(fd), iface)
	}); cerr != nil {
		return cerr
	}
	return err
}

// dialUDP dials a connected UDP socket through a Dialer (which may carry a
// Control hook for device binding or a LocalAddr for source binding).
func dialUDP(d *net.Dialer, raddr *net.UDPAddr) (*net.UDPConn, error) {
	conn, err := d.Dial("udp", raddr.String())
	if err != nil {
		return nil, err
	}
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("dial returned %T, want *net.UDPConn", conn)
	}
	return uc, nil
}
