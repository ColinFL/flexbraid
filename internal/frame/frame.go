// Package frame implements the FlexBraid on-the-wire frame format.
// Wire layout is specified in docs/PROTOCOL.md.
//
// A sealed frame on the wire is: header(28) + encrypted payload + auth tag(16).
// The crypto layer authenticates the header and encrypts the payload; this
// package deals with the header and plaintext payload only.
package frame

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// Magic identifies FlexBraid frames ("FLXB", big-endian).
	Magic = 0x464C5842
	// Version is the current wire protocol version. 0x02 since the M5.5 PFS
	// key exchange and the server-authoritative FEC/MTU announcement
	// (KEX_ACK ServerAnnounce): both made the payload incompatible with 0x01
	// peers, which would otherwise fail cryptically mid-session instead of
	// being refused at the header check. Bump this on every wire-breaking
	// change (see docs/PROTOCOL.md §7).
	Version = 0x02
	// HeaderSize is the size of the frame header in bytes.
	HeaderSize = 28
	// TagSize is the size of the AEAD auth tag appended after the payload.
	TagSize = 16
	// MaxPayload is the largest representable payload (u16 length field).
	MaxPayload = 1<<16 - 1
)

// Frame flags (wire, bit 0 is the LSB of the flags byte).
const (
	// FlagFECParity marks a payload as FEC parity, not inner data (M2+).
	FlagFECParity uint8 = 1 << 0
	// FlagKeepalive marks a liveness/RTT probe (no inner data).
	FlagKeepalive uint8 = 1 << 1
	// FlagControl marks a control-plane frame (handshake, telemetry).
	FlagControl uint8 = 1 << 2
	// FlagFirst marks the first frame of a session (client handshake).
	FlagFirst uint8 = 1 << 3
	// FlagPong marks a keepalive reply (server → client, RTT probe echo).
	FlagPong uint8 = 1 << 4
	// FlagKex marks the key-exchange ACK (server → client, M5.5 PFS): the
	// payload carries the server's ephemeral X25519 public key, sealed under
	// the base (PSK) key so the client can read it before the session key
	// exists.
	FlagKex uint8 = 1 << 5
	// FlagPassSeq marks a pass-through (uncoded) frame whose BlockSeq field
	// carries a per-path monotonic frame counter instead of a FEC block
	// id. The receiver counts gaps in that counter per path — the raw,
	// per-WAN loss signal that works under sustained load, where keepalive
	// probes are suppressed by traffic (design: docs/DESIGN.md §15.x,
	// adaptive trigger). Zero in coded frames.
	FlagPassSeq uint8 = 1 << 6
)

// Frame is a decoded or to-be-encoded frame. Payload holds the plaintext
// inner datagram (or control data); the auth tag is owned by the crypto layer.
// For pass-through frames (FlagPassSeq set) BlockSeq holds a per-path frame
// counter; for coded frames it holds the FEC block id.
type Frame struct {
	Version   uint8
	Flags     uint8
	SessionID uint64
	Seq       uint32
	BlockSeq  uint32
	Payload   []byte
}

// HasFlag reports whether flag is set.
func (f *Frame) HasFlag(flag uint8) bool { return f.Flags&flag != 0 }

// Encode serialises the header + payload (without the auth tag) into a new
// buffer. The result is the plaintext input for crypto.Seal.
func (f *Frame) Encode() ([]byte, error) {
	if len(f.Payload) > MaxPayload {
		return nil, fmt.Errorf("frame payload too large: %d > %d", len(f.Payload), MaxPayload)
	}
	buf := make([]byte, HeaderSize+len(f.Payload))
	binary.BigEndian.PutUint32(buf[0:], Magic)
	buf[4] = Version
	buf[5] = f.Flags
	// buf[6:8] reserved
	binary.BigEndian.PutUint64(buf[8:], f.SessionID)
	binary.BigEndian.PutUint32(buf[16:], f.Seq)
	binary.BigEndian.PutUint32(buf[20:], f.BlockSeq)
	binary.BigEndian.PutUint16(buf[24:], uint16(len(f.Payload)))
	// buf[26:28] reserved
	copy(buf[HeaderSize:], f.Payload)
	return buf, nil
}

// DecodeHeader parses and validates the header of a sealed frame. It is
// cheap and intended to run before authentication/decryption so that the
// anti-replay filter can act on the sequence number early. Payload is nil.
func DecodeHeader(b []byte) (*Frame, error) {
	if len(b) < HeaderSize {
		return nil, errors.New("frame too short")
	}
	if binary.BigEndian.Uint32(b[0:]) != Magic {
		return nil, errors.New("bad magic")
	}
	if b[4] != Version {
		return nil, fmt.Errorf("unsupported protocol version %d", b[4])
	}
	return &Frame{
		Version:   b[4],
		Flags:     b[5],
		SessionID: binary.BigEndian.Uint64(b[8:]),
		Seq:       binary.BigEndian.Uint32(b[16:]),
		BlockSeq:  binary.BigEndian.Uint32(b[20:]),
	}, nil
}

// Decode parses a frame whose header+plaintext payload was already verified
// and decrypted by crypto.Open (i.e. the buffer length matches the header's
// payload length exactly).
func Decode(b []byte) (*Frame, error) {
	f, err := DecodeHeader(b)
	if err != nil {
		return nil, err
	}
	plen := int(binary.BigEndian.Uint16(b[24:]))
	if len(b) != HeaderSize+plen {
		return nil, fmt.Errorf("frame length mismatch: header says %d payload bytes, buffer has %d", plen, len(b)-HeaderSize)
	}
	f.Payload = b[HeaderSize : HeaderSize+plen]
	return f, nil
}
