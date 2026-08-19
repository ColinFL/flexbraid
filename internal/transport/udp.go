package transport

import (
	"errors"
	"fmt"
	"net"
	"syscall"
)

// UDP is the plain encrypted-UDP wire format (transport mode "udp").
//
// Client mode dials the FlexBraid server once (Send → the server), pinning
// the socket to the WAN's device or source address when configured (Bind).
// Server mode binds the listen socket and uses SendTo for per-path endpoints.
type UDP struct {
	id       string
	local    string // server: bind address; client: "" (ephemeral)
	remote   string // client: server address; server: ""
	bind     Bind   // client: uplink pinning (iface → local_ip fallback)
	conn     *net.UDPConn
	remoteIP *net.UDPAddr // client mode: the dialed peer

	// readBuf is a single-reader scratch buffer: each transport has exactly
	// one Recv loop (client recvLoop / server wanLoop), so one buffer can
	// be reused. Recv returns an exact-size copy, so the returned slice is
	// owned by the caller (FEC blocks may hold it until flushed).
	readBuf [65535]byte
}

// NewUDP creates a UDP transport. In client mode remote is required; in
// server mode local is required.
func NewUDP(id, local, remote string, bind Bind) *UDP {
	return &UDP{id: id, local: local, remote: remote, bind: bind}
}

func (u *UDP) ID() string { return u.id }

// LocalAddr returns the bound local address (nil before Open).
func (u *UDP) LocalAddr() net.Addr {
	if u.conn == nil {
		return nil
	}
	return u.conn.LocalAddr()
}

func (u *UDP) Open() error {
	if u.remote != "" {
		return u.openClient()
	}
	// server mode: bind
	laddr, err := net.ResolveUDPAddr("udp", u.local)
	if err != nil {
		return fmt.Errorf("udp[%s]: resolve %s: %w", u.id, u.local, err)
	}
	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		return fmt.Errorf("udp[%s]: listen %s: %w", u.id, u.local, err)
	}
	u.conn = conn
	return nil
}

// openClient dials the server, pinning the socket to the WAN's device
// (privileged) or source address (fallback). Without binding, the kernel
// routes all WAN sockets through the default route and multi-WAN balancing
// collapses onto one uplink.
func (u *UDP) openClient() error {
	raddr, err := net.ResolveUDPAddr("udp", u.remote)
	if err != nil {
		return fmt.Errorf("udp[%s]: resolve %s: %w", u.id, u.remote, err)
	}
	conn, err := u.dialBound(raddr)
	if err != nil {
		return fmt.Errorf("udp[%s]: dial %s: %w", u.id, u.remote, err)
	}
	u.conn = conn
	u.remoteIP = raddr
	return nil
}

// dialBound tries, in order: device binding (iface) → source binding
// (local_ip) → plain dial.
//
// A device-bind failure falls back to local_ip when one is configured —
// both for permission errors (unprivileged daemons) and for platforms
// without device binding at all (FreeBSD 15 removed IP_BOUND_IF). When no
// fallback exists the error is returned with an actionable hint, because a
// silently unbound socket routes through the default route and multi-WAN
// collapses onto one uplink without any visible sign.
func (u *UDP) dialBound(raddr *net.UDPAddr) (*net.UDPConn, error) {
	if u.bind.Iface != "" || u.bind.FIB >= 0 {
		iface := u.bind.Iface
		fib := u.bind.FIB
		d := &net.Dialer{Control: func(network, address string, c syscall.RawConn) error {
			return bindToDevice(c, iface, fib)
		}}
		conn, err := dialUDP(d, raddr)
		if err == nil {
			return conn, nil
		}
		fallback := errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES) ||
			errors.Is(err, ErrDeviceBindUnsupported)
		if !fallback {
			return nil, err // real failure (bad interface name, etc.)
		}
		if u.bind.LocalIP == "" {
			return nil, fmt.Errorf("bind to device %q failed (%w); set wan.local_ip to bind the source address instead, or run with sufficient privileges", u.bind.Iface, err)
		}
	}
	if u.bind.LocalIP != "" {
		ip := net.ParseIP(u.bind.LocalIP)
		if ip == nil {
			return nil, fmt.Errorf("invalid local_ip %q", u.bind.LocalIP)
		}
		d := &net.Dialer{LocalAddr: &net.UDPAddr{IP: ip}}
		return dialUDP(d, raddr)
	}
	return net.DialUDP("udp", nil, raddr)
}

func (u *UDP) Send(b []byte) error {
	if u.remoteIP == nil {
		return fmt.Errorf("udp[%s]: Send requires client mode", u.id)
	}
	_, err := u.conn.Write(b)
	return err
}

func (u *UDP) SendTo(addr net.Addr, b []byte) error {
	ua, ok := addr.(*net.UDPAddr)
	if !ok {
		return fmt.Errorf("udp[%s]: SendTo requires *net.UDPAddr, got %T", u.id, addr)
	}
	_, err := u.conn.WriteToUDP(b, ua)
	return err
}

func (u *UDP) Recv() ([]byte, net.Addr, error) {
	n, addr, err := u.conn.ReadFromUDP(u.readBuf[:])
	if err != nil {
		return nil, nil, err
	}
	// Exact-size copy: the scratch buffer is reused on the next call, and
	// the FEC decoder may hold the payload until its block is flushed.
	out := make([]byte, n)
	copy(out, u.readBuf[:n])
	return out, addr, nil
}

func (u *UDP) Close() error {
	if u.conn != nil {
		return u.conn.Close()
	}
	return nil
}
