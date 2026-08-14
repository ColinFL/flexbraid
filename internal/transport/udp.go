package transport

import (
	"fmt"
	"net"
)

// UDP is the plain encrypted-UDP wire format (transport mode "udp").
//
// Client mode dials the FlexBraid server once (Send → the server). Server
// mode binds the listen socket and uses SendTo for per-path endpoints.
type UDP struct {
	id       string
	local    string // server: bind address; client: "" (ephemeral)
	remote   string // client: server address; server: ""
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
func NewUDP(id, local, remote string) *UDP {
	return &UDP{id: id, local: local, remote: remote}
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
		raddr, err := net.ResolveUDPAddr("udp", u.remote)
		if err != nil {
			return fmt.Errorf("udp[%s]: resolve %s: %w", u.id, u.remote, err)
		}
		conn, err := net.DialUDP("udp", nil, raddr)
		if err != nil {
			return fmt.Errorf("udp[%s]: dial %s: %w", u.id, u.remote, err)
		}
		u.conn = conn
		u.remoteIP = raddr
		return nil
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
