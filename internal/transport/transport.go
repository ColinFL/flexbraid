// Package transport defines the per-WAN wire-format abstraction and its
// implementations.
//
// A Transport is one physical path between a FlexBraid client and server. The
// scheduler (M3) will pick a transport per frame; the session layer tracks a
// per-path endpoint per transport (see docs/DESIGN.md §9.1). Wire formats
// beyond UDP (faketcp, icmp) arrive in M4 and plug in behind this interface.
package transport

import "net"

// Transport is one physical path between client and server.
type Transport interface {
	// ID returns the WAN identifier (from config, e.g. "w1").
	ID() string
	// Open prepares the transport (client: dials the server; server: binds
	// the listen socket).
	Open() error
	// LocalAddr returns the bound local address, or nil before Open.
	LocalAddr() net.Addr
	// Send sends a sealed frame to the default peer (client mode).
	Send(b []byte) error
	// SendTo sends a sealed frame to an explicit peer (server mode, per-path
	// endpoints).
	SendTo(addr net.Addr, b []byte) error
	// Recv returns the next sealed frame and its source address.
	Recv() ([]byte, net.Addr, error)
	// Close releases the socket.
	Close() error
}
