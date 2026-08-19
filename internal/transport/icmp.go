// ICMP is the last-resort wire format (transport mode "icmp"): data rides
// in ICMP echo request/reply payloads (docs/DESIGN.md §8.2), so a link
// that blocks or throttles UDP/TCP still carries the tunnel — to DPI it is
// ordinary ping traffic.
//
// ICMP tunnels are PULL by nature: a host may only send echo REPLIES, so
// server→client data must wait for the client's next request. The
// transport hides this behind the Transport interface:
//
//   - client: Send(b) → echo request with payload b; Recv() → the reply
//     payload (server→client data).
//   - server: Recv() → client payload (and the request's source); the
//     data queued by SendTo(addr, b) since the last request is appended
//     to the reply — the request is the tick that drains the queue. With
//     FlexBraid's keepalive probes flowing every probe_interval this is a
//     ≤1 s delivery latency in the server→client direction.
//
// Requires root/CAP_NET_RAW (raw ICMP sockets) and IPv4.
package transport

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

const (
	icmpTypeEchoReply   = 0
	icmpTypeEchoRequest = 8
	icmpHdrLen          = 8
)

// ICMP implements Transport over raw ICMP echo packets.
type ICMP struct {
	id     string
	local  string // server: bind address; client: our source "ip:port" (port ignored)
	remote string // client: server address; server: ""
	bind   Bind

	fd   int // raw socket (SOCK_RAW, IPPROTO_ICMP)
	srv  bool
	open bool

	// Client-mode addressing (resolved at Open).
	clientDstIP net.IP
	myID        uint16
	mySeq       uint32

	// Server mode: the listen identifier is not used for filtering
	// (replies must mirror the request's ID); the server answers any
	// echo request.
	serverPort uint16 // unused, kept for symmetry

	// replyQueue buffers server→client data per peer: the next echo
	// request drains it (pull model). Bounded per peer; overflow drops
	// the oldest queued payload.
	mu         sync.Mutex
	replyQueue map[string][][]byte
	queueBytes map[string]int
}

const maxQueuePerPeer = 1 << 20 // 1 MiB of pending server→client data

// NewICMP creates an ICMP transport. Client mode: remote is the server
// address; local is our source (port ignored). Server mode: local is the
// bind address (port ignored; replies mirror the request's ID).
func NewICMP(id, local, remote string, bind Bind) *ICMP {
	return &ICMP{
		id: id, local: local, remote: remote, bind: bind,
		fd:         -1,
		replyQueue: make(map[string][][]byte),
		queueBytes: make(map[string]int),
	}
}

func (i *ICMP) ID() string { return i.id }

func (i *ICMP) LocalAddr() net.Addr {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.srv {
		return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	return &net.UDPAddr{IP: i.clientDstIP, Port: int(i.myID)}
}

func (i *ICMP) Open() error {
	if i.fd >= 0 {
		return errors.New("icmp: already open")
	}
	if i.remote != "" {
		return i.openClient()
	}
	return i.openServer()
}

func (i *ICMP) openClient() error {
	raddr, err := net.ResolveUDPAddr("udp", i.remote)
	if err != nil {
		return fmt.Errorf("icmp[%s]: resolve %s: %w", i.id, i.remote, err)
	}
	if raddr.IP.To4() == nil {
		return fmt.Errorf("icmp[%s]: only IPv4 is supported (server %s)", i.id, i.remote)
	}
	fd, err := openICMPSocket(i.id, i.bind)
	if err != nil {
		return err
	}
	i.fd = fd
	i.srv = false
	i.clientDstIP = raddr.IP.To4()
	i.myID = uint16(randPort())
	return nil
}

func (i *ICMP) openServer() error {
	laddr, err := net.ResolveUDPAddr("udp", i.local)
	if err != nil {
		return fmt.Errorf("icmp[%s]: resolve %s: %w", i.id, i.local, err)
	}
	if laddr.IP != nil && laddr.IP.To4() == nil && !laddr.IP.IsUnspecified() {
		return fmt.Errorf("icmp[%s]: only IPv4 is supported (listen %s)", i.id, i.local)
	}
	fd, err := openICMPSocket(i.id, i.bind)
	if err != nil {
		return err
	}
	i.fd = fd
	i.srv = true
	return nil
}

func (i *ICMP) Close() error {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.fd >= 0 {
		err := closeRawSocket(i.fd)
		i.fd = -1
		return err
	}
	return nil
}

// Send sends a sealed frame as an echo request (client mode). The reply
// carries the server's queued data and is returned by the next Recv.
func (i *ICMP) Send(b []byte) error {
	i.mu.Lock()
	i.mySeq++
	seq := i.mySeq
	i.mu.Unlock()
	pkt := buildEcho(icmpTypeEchoRequest, i.myID, seq, b)
	return i.sendTo(pkt, i.clientDstIP)
}

// SendTo queues a sealed frame for a peer (server mode): it is appended to
// that peer's reply and delivered with the next echo request from it.
func (i *ICMP) SendTo(addr net.Addr, b []byte) error {
	ua, ok := addr.(*net.UDPAddr)
	if !ok || ua.IP.To4() == nil {
		return fmt.Errorf("icmp[%s]: bad peer address %v", i.id, addr)
	}
	key := addrKey(ua)
	// The reply is assembled inside Recv (it must mirror the request's
	// ID/seq); here we only queue the payload.
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.queueBytes[key]+len(b) > maxQueuePerPeer {
		// Overflow: drop the oldest queued payload to stay bounded.
		q := i.replyQueue[key]
		if len(q) > 0 {
			i.queueBytes[key] -= len(q[0])
			q = q[1:]
			i.replyQueue[key] = q
		}
	}
	i.replyQueue[key] = append(i.replyQueue[key], b)
	i.queueBytes[key] += len(b)
	return nil
}

// Recv returns the next client payload and its source address.
//
// Server mode: on each echo request the peer's queued reply data is
// flushed (concatenated, up to the path MTU) and sent back as the echo
// reply; the request's own payload is returned. Client mode: returns the
// echo reply payload from the server.
func (i *ICMP) Recv() ([]byte, net.Addr, error) {
	buf := make([]byte, 65535)
	for {
		n, err := readRaw(i.fd, buf)
		if err != nil {
			return nil, nil, err
		}
		frame, src, rtype, id, ok := parseEcho(buf[:n])
		if !ok {
			continue
		}
		if i.srv {
			if rtype != icmpTypeEchoRequest {
				continue
			}
			// Drain this peer's reply queue into the response. The
			// reply must mirror the request's ID/seq so the client's
			// filter accepts it.
			key := src.String()
			i.mu.Lock()
			q := i.replyQueue[key]
			i.replyQueue[key] = nil
			i.queueBytes[key] = 0
			i.mu.Unlock()
			var reply []byte
			for _, p := range q {
				if len(reply)+len(p) > 1472-icmpHdrLen {
					break
				}
				reply = append(reply, p...)
			}
			if err := i.sendEchoReply(src, buf, reply); err != nil {
				return nil, nil, err
			}
			// Copy: frame aliases the read buffer, which the next
			// readRaw overwrites.
			out := make([]byte, len(frame))
			copy(out, frame)
			return out, src, nil
		}
		// Client: only replies with OUR identifier FROM THE SERVER (the
		// raw socket sees every ICMP echo in the system; a spoofed reply
		// with our id must not be accepted).
		if rtype != icmpTypeEchoReply || id != i.myID || !src.IP.Equal(i.clientDstIP) {
			continue
		}
		out := make([]byte, len(frame))
		copy(out, frame)
		return out, src, nil
	}
}

// sendEchoReply answers an echo request with the queued data. The request
// packet supplies ID/seq (mirrored) — parseEcho already validated it.
func (i *ICMP) sendEchoReply(src *net.UDPAddr, reqPkt []byte, reply []byte) error {
	// The request's ICMP header: type(1) code(1) csum(2) id(2) seq(2).
	// Reuse the request header, flip the type, clear checksum, append the
	// reply payload and recompute. Offset of the ICMP header inside the
	// received datagram: parseEcho skipped the IP header (ihl).
	icmpOff := reqICMPOffset(reqPkt)
	if icmpOff < 0 {
		return errors.New("icmp: bad request packet")
	}
	out := make([]byte, icmpHdrLen+len(reply))
	copy(out, reqPkt[icmpOff:icmpOff+icmpHdrLen])
	out[0] = icmpTypeEchoReply
	binary.BigEndian.PutUint16(out[2:4], 0) // checksum
	copy(out[icmpHdrLen:], reply)
	binary.BigEndian.PutUint16(out[2:4], icmpChecksum(out))
	return i.sendTo(out, src.IP.To4())
}

func (i *ICMP) sendTo(pkt []byte, dst net.IP) error {
	if i.fd < 0 {
		return errors.New("icmp: not open")
	}
	return sendICMP(i.fd, pkt, dst)
}

// --- packet construction / parsing ----------------------------------------

// buildEcho builds one ICMP echo packet (request or reply).
func buildEcho(typ byte, id uint16, seq uint32, payload []byte) []byte {
	pkt := make([]byte, icmpHdrLen+len(payload))
	pkt[0] = typ
	binary.BigEndian.PutUint16(pkt[4:6], id)
	binary.BigEndian.PutUint16(pkt[6:8], uint16(seq))
	copy(pkt[icmpHdrLen:], payload)
	binary.BigEndian.PutUint16(pkt[2:4], icmpChecksum(pkt))
	return pkt
}

// parseEcho decodes a received IPv4 datagram and returns the ICMP payload,
// source address, type and identifier. Only well-formed echo packets with
// a valid checksum are accepted.
func parseEcho(b []byte) (payload []byte, src *net.UDPAddr, rtype byte, id uint16, ok bool) {
	if len(b) < ipHdrLen+icmpHdrLen {
		return nil, nil, 0, 0, false
	}
	if b[0]>>4 != 4 {
		return nil, nil, 0, 0, false // IPv4 only
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < ipHdrLen || len(b) < ihl+icmpHdrLen {
		return nil, nil, 0, 0, false
	}
	if b[9] != 1 {
		return nil, nil, 0, 0, false // ICMP only
	}
	if frag := binary.BigEndian.Uint16(b[6:8]) & 0x1fff; frag != 0 {
		return nil, nil, 0, 0, false
	}
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if total == 0 || total > len(b) {
		total = len(b)
	}
	srcIP := net.IP(b[12:16]).To4()
	if srcIP == nil {
		return nil, nil, 0, 0, false
	}
	icmp := b[ihl:total]
	rtype = icmp[0]
	if rtype != icmpTypeEchoRequest && rtype != icmpTypeEchoReply {
		return nil, nil, 0, 0, false
	}
	if icmpChecksum(icmp) != 0 {
		return nil, nil, 0, 0, false
	}
	id = binary.BigEndian.Uint16(icmp[4:6])
	return icmp[icmpHdrLen:], &net.UDPAddr{IP: srcIP, Port: 0}, rtype, id, true
}

// reqICMPOffset finds the ICMP header offset inside a received datagram
// (IPv4 header length varies); -1 if the packet is malformed.
func reqICMPOffset(b []byte) int {
	if len(b) < ipHdrLen {
		return -1
	}
	ihl := int(b[0]&0x0f) * 4
	if ihl < ipHdrLen || len(b) < ihl+icmpHdrLen {
		return -1
	}
	return ihl
}

// icmpChecksum computes the ICMP checksum (RFC 1071, over the whole packet).
func icmpChecksum(b []byte) uint16 {
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
