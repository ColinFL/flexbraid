// FakeTCP is the "TCP-disguised" wire format (transport mode "faketcp"),
// derived from udp2raw's FakeTCP (docs/DESIGN.md §8.2): the tunnel sends
// IPv4+TCP segments with a simulated 3-way handshake and seq/ack counting,
// so DPI sees ordinary TCP traffic instead of a UDP stream.
//
// It is NOT a TCP implementation — there is no retransmit, window or
// connection state. The kernel never learns about these segments: they go
// out through a raw socket (IP_HDRINCL), which is why FakeTCP requires
// root/CAP_NET_RAW and why RST suppression is REQUIRED in NAT setups —
// the kernel answers the fake handshake with RST (closed port), and NAT
// boxes tear down the mapping on RST:
//
//	Linux:  iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
//	FreeBSD: pf: pass out proto tcp flags RST ... (or drop RST)
//
// Both ends must suppress RST. See docs/CONFIG.md "faketcp".
package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

const (
	tcpFlagFIN = 0x01
	tcpFlagSYN = 0x02
	tcpFlagRST = 0x04
	tcpFlagPSH = 0x08
	tcpFlagACK = 0x10

	ipHdrLen  = 20
	tcpHdrLen = 20
)

// peerState tracks the fake-TCP counters of one remote endpoint (server
// side: one per client path; client side: the single server).
type peerState struct {
	mySeq   uint32
	peerSeq uint32
	sent    bool // at least one segment sent (SYN handshake started/completed)
}

// FakeTCP implements Transport over raw IPv4/TCP segments.
type FakeTCP struct {
	id     string
	local  string // server: bind address (host:port); client: our source (host:port)
	remote string // client: server address; server: ""
	bind   Bind

	fd   int  // raw socket (SOCK_RAW, IPPROTO_TCP, IP_HDRINCL) for RX+TX
	srv  bool // server mode: per-peer addressing via SendTo
	open bool

	// Client-mode addressing (resolved at Open).
	clientDstIP   net.IP
	clientSrcPort uint16
	clientDstPort uint16

	// Server-mode bind.
	serverPort uint16

	mu    sync.Mutex
	peers map[string]*peerState // server: per-path state

	// srcCache caches the local source IP for a remote IP (routing trick).
	srcMu  sync.Mutex
	srcFor map[string]net.IP
}

// NewFakeTCP creates a FakeTCP transport. Client mode: remote is the
// server address; local is our source "ip:port" (port 0 = random). Server
// mode: local is the bind address, remote is empty.
func NewFakeTCP(id, local, remote string, bind Bind) *FakeTCP {
	return &FakeTCP{
		id: id, local: local, remote: remote, bind: bind,
		fd:     -1,
		peers:  make(map[string]*peerState),
		srcFor: make(map[string]net.IP),
	}
}

func (f *FakeTCP) ID() string { return f.id }

// LocalAddr returns the local address (client: our src; server: bind).
func (f *FakeTCP) LocalAddr() net.Addr {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.srv {
		return &net.UDPAddr{IP: net.IPv4zero, Port: int(f.serverPort)}
	}
	return &net.UDPAddr{IP: f.clientSrcIP(), Port: int(f.clientSrcPort)}
}

func (f *FakeTCP) clientSrcIP() net.IP {
	f.srcMu.Lock()
	defer f.srcMu.Unlock()
	if ip, ok := f.srcFor[f.clientDstIP.String()]; ok {
		return ip
	}
	return net.IPv4zero
}

// Open prepares the raw socket. Client mode resolves the server and picks
// our source address (routing trick); server mode binds the port filter.
func (f *FakeTCP) Open() error {
	if f.fd >= 0 {
		return errors.New("faketcp: already open")
	}
	if f.remote != "" {
		return f.openClient()
	}
	return f.openServer()
}

func (f *FakeTCP) openClient() error {
	raddr, err := net.ResolveUDPAddr("udp", f.remote)
	if err != nil {
		return fmt.Errorf("faketcp[%s]: resolve %s: %w", f.id, f.remote, err)
	}
	if raddr.IP.To4() == nil {
		return fmt.Errorf("faketcp[%s]: only IPv4 is supported (server %s)", f.id, f.remote)
	}
	dstIP := raddr.IP.To4()

	// Our source IP: the address the kernel would route to the server.
	srcIP := f.localIPFor(dstIP)
	srcPort := uint16(0)
	if laddr, err := net.ResolveUDPAddr("udp", f.local); err == nil && laddr.Port > 0 {
		srcPort = uint16(laddr.Port)
	} else if srcPort == 0 {
		srcPort = uint16(randPort())
	}

	fd, err := openRawSocket(f.id, f.bind)
	if err != nil {
		return err
	}
	f.fd = fd
	f.srv = false
	f.clientDstIP = dstIP
	f.clientDstPort = uint16(raddr.Port)
	f.clientSrcPort = srcPort
	f.srcFor[dstIP.String()] = srcIP
	f.peers["server"] = &peerState{mySeq: randSeq()}
	return nil
}

func (f *FakeTCP) openServer() error {
	laddr, err := net.ResolveUDPAddr("udp", f.local)
	if err != nil {
		return fmt.Errorf("faketcp[%s]: resolve %s: %w", f.id, f.local, err)
	}
	if laddr.IP != nil && laddr.IP.To4() == nil && !laddr.IP.IsUnspecified() {
		return fmt.Errorf("faketcp[%s]: only IPv4 is supported (listen %s)", f.id, f.local)
	}
	fd, err := openRawSocket(f.id, f.bind)
	if err != nil {
		return err
	}
	f.fd = fd
	f.srv = true
	f.serverPort = uint16(laddr.Port)
	return nil
}

func (f *FakeTCP) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fd >= 0 {
		err := closeRawSocket(f.fd)
		f.fd = -1
		return err
	}
	return nil
}

// Send sends a sealed frame to the default peer (client mode).
func (f *FakeTCP) Send(b []byte) error {
	f.mu.Lock()
	st := f.peers["server"]
	if st == nil {
		f.mu.Unlock()
		return errors.New("faketcp: not open")
	}
	srcIP := f.clientSrcIP()
	seq := st.mySeq
	var flags byte
	if st.sent {
		flags = tcpFlagPSH | tcpFlagACK
	} else {
		flags = tcpFlagSYN // fake handshake: first segment carries data too
		st.sent = true
	}
	seg := buildSegment(srcIP, f.clientDstIP, f.clientSrcPort, f.clientDstPort, seq, st.peerSeq, flags, b)
	st.mySeq += seqAdvance(len(b))
	f.mu.Unlock()
	_, err := writeRaw(f.fd, seg, f.clientDstIP)
	return err
}

// SendTo sends a sealed frame to an explicit peer (server mode).
func (f *FakeTCP) SendTo(addr net.Addr, b []byte) error {
	ua, ok := addr.(*net.UDPAddr)
	if !ok || ua.IP.To4() == nil {
		return fmt.Errorf("faketcp[%s]: bad peer address %v", f.id, addr)
	}
	dstIP := ua.IP.To4()
	key := addrKey(ua)
	srcIP := f.localIPFor(dstIP)

	f.mu.Lock()
	st := f.peers[key]
	if st == nil {
		st = &peerState{mySeq: randSeq(), peerSeq: 0}
		f.peers[key] = st
	}
	var flags byte
	if st.sent {
		flags = tcpFlagPSH | tcpFlagACK
	} else {
		flags = tcpFlagSYN | tcpFlagACK
		st.sent = true
	}
	seg := buildSegment(srcIP, dstIP, f.serverPort, uint16(ua.Port), st.mySeq, st.peerSeq, flags, b)
	st.mySeq += seqAdvance(len(b))
	f.mu.Unlock()
	_, err := writeRaw(f.fd, seg, dstIP)
	return err
}

// Recv returns the next sealed frame and its source address.
func (f *FakeTCP) Recv() ([]byte, net.Addr, error) {
	buf := make([]byte, 65535)
	for {
		n, err := readRaw(f.fd, buf)
		if err != nil {
			return nil, nil, err
		}
		frame, src, dstPort, syn, seq, ok := parseSegment(buf[:n])
		if !ok {
			continue
		}
		f.mu.Lock()
		if f.srv {
			if dstPort != f.serverPort {
				f.mu.Unlock()
				continue
			}
		} else {
			if dstPort != f.clientSrcPort || !src.IP.Equal(f.clientDstIP) {
				f.mu.Unlock()
				continue
			}
		}
		// Track the peer's sequence: our ACK must follow theirs.
		key := src.String()
		if !f.srv {
			key = "server"
		}
		st := f.peers[key]
		if st == nil {
			st = &peerState{mySeq: randSeq()}
			f.peers[key] = st
		}
		if syn {
			st.peerSeq = seq + 1
		} else {
			st.peerSeq = seq + uint32(maxI(1, len(frame)))
		}
		f.mu.Unlock()
		return frame, src, nil
	}
}

// --- packet construction / parsing ----------------------------------------

// buildSegment assembles the IPv4+TCP wire image for one fake segment.
func buildSegment(src, dst net.IP, srcPort, dstPort uint16, seq, ack uint32, flags byte, payload []byte) []byte {
	total := ipHdrLen + tcpHdrLen + len(payload)
	seg := make([]byte, total)
	// IP header.
	seg[0] = 0x45
	binary.BigEndian.PutUint16(seg[2:4], uint16(total))
	binary.BigEndian.PutUint16(seg[4:6], uint16(randID()))
	seg[8] = 64 // ttl
	seg[9] = 6  // TCP
	copy(seg[12:16], src.To4())
	copy(seg[16:20], dst.To4())
	binary.BigEndian.PutUint16(seg[10:12], ipChecksum(seg[:ipHdrLen]))
	// TCP header.
	binary.BigEndian.PutUint16(seg[ipHdrLen:ipHdrLen+2], srcPort)
	binary.BigEndian.PutUint16(seg[ipHdrLen+2:ipHdrLen+4], dstPort)
	binary.BigEndian.PutUint32(seg[ipHdrLen+4:ipHdrLen+8], seq)
	binary.BigEndian.PutUint32(seg[ipHdrLen+8:ipHdrLen+12], ack)
	seg[ipHdrLen+12] = 5 << 4 // data offset 20 bytes
	seg[ipHdrLen+13] = flags
	binary.BigEndian.PutUint16(seg[ipHdrLen+14:ipHdrLen+16], 65535) // window
	copy(seg[ipHdrLen+tcpHdrLen:], payload)
	binary.BigEndian.PutUint16(seg[ipHdrLen+16:ipHdrLen+18], tcpChecksum(src, dst, seg[ipHdrLen:]))
	return seg
}

// parseSegment decodes one received IPv4+TCP datagram. Returns the TCP
// payload, source address, destination port, whether SYN was set, the TCP
// sequence and whether the segment is usable (valid IP/TCP, not RST/FIN).
func parseSegment(b []byte) (payload []byte, src *net.UDPAddr, dstPort uint16, syn bool, seq uint32, ok bool) {
	if len(b) < ipHdrLen {
		return nil, nil, 0, false, 0, false
	}
	if b[0]>>4 != 4 {
		return nil, nil, 0, false, 0, false // IPv4 only
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < ipHdrLen || len(b) < ihl+tcpHdrLen {
		return nil, nil, 0, false, 0, false
	}
	if b[9] != 6 {
		return nil, nil, 0, false, 0, false // TCP only
	}
	// Fragmented datagrams carry no usable payload for us.
	if frag := binary.BigEndian.Uint16(b[6:8]) & 0x1fff; frag != 0 {
		return nil, nil, 0, false, 0, false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total == 0 || total > len(b) {
		total = len(b)
	}
	srcIP := net.IP(b[12:16]).To4()
	if srcIP == nil {
		return nil, nil, 0, false, 0, false
	}
	tcp := b[ihl:total]
	dstPort = binary.BigEndian.Uint16(tcp[2:4])
	flags := tcp[13]
	if flags&(tcpFlagRST|tcpFlagFIN) != 0 {
		return nil, nil, 0, false, 0, false
	}
	if !validTCPChecksum(srcIP, net.IP(b[16:20]).To4(), tcp) {
		return nil, nil, 0, false, 0, false
	}
	off := int(tcp[12]>>4) * 4
	if off < tcpHdrLen || off > len(tcp) {
		return nil, nil, 0, false, 0, false
	}
	seq = binary.BigEndian.Uint32(tcp[4:8])
	syn = flags&tcpFlagSYN != 0
	return tcp[off:], &net.UDPAddr{IP: srcIP, Port: int(binary.BigEndian.Uint16(tcp[0:2]))}, dstPort, syn, seq, true
}

// seqAdvance mimics a real TCP sequence walk: a SYN consumes one sequence
// number, data advances by its byte length (empty segments advance one).
func seqAdvance(dataLen int) uint32 {
	if dataLen > 0 {
		return uint32(dataLen)
	}
	return 1
}

// ipChecksum computes the standard IPv4 header checksum.
func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum over the pseudo-header + segment.
func tcpChecksum(src, dst net.IP, tcp []byte) uint16 {
	return checksumWithPseudo(src, dst, tcp)
}

func checksumWithPseudo(src, dst net.IP, tcp []byte) uint16 {
	var sum uint32
	psum := func(b []byte) {
		for i := 0; i+1 < len(b); i += 2 {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		}
		if len(b)%2 == 1 {
			sum += uint32(b[len(b)-1]) << 8
		}
	}
	psum(src.To4())
	psum(dst.To4())
	sum += 6 // protocol TCP
	sum += uint32(len(tcp))
	for i := 0; i+1 < len(tcp); i += 2 {
		sum += uint32(tcp[i])<<8 | uint32(tcp[i+1])
	}
	if len(tcp)%2 == 1 {
		sum += uint32(tcp[len(tcp)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// validTCPChecksum verifies a received segment's TCP checksum.
func validTCPChecksum(src, dst net.IP, tcp []byte) bool {
	if len(tcp) < tcpHdrLen {
		return false
	}
	return checksumWithPseudo(src, dst, tcp) == 0
}

// addrKey renders a UDP-style address as a map key.
func addrKey(a *net.UDPAddr) string { return a.String() }

func maxI(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Cosmetic sequence/port/ID generators: fake TCP is not a real transport,
// so nothing cryptographic is needed — the values only have to look right
// to DPI and keep NAT mappings alive.
func randSeq() uint32  { return randUint32() }
func randPort() uint32 { return 1024 + randUint32()%60000 }
func randID() uint32   { return randUint32() & 0xffff }
