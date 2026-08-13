// Package crypto implements the FlexBraid channel security:
//
//   - key derivation: HKDF-SHA256 (RFC 5869) expands the shared PSK into a
//     32-byte channel key (see docs/DESIGN.md §11 — PSK is always required,
//     there is no unauthenticated ephemeral-key path);
//   - AEAD sealing: ChaCha20-Poly1305 (default) or AES-256-GCM; the frame
//     header is authenticated, the payload encrypted;
//   - anti-replay: a sliding bitmap window whose size must be >= the
//     delivery-buffer window (docs/DESIGN.md §5) so that legitimate frames
//     reordered by multi-path delivery are never rejected.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

// NonceDirection separates the two channel directions so the same key is
// usable both ways without nonce reuse.
type NonceDirection byte

const (
	// DirClientToServer marks frames sent by the client.
	DirClientToServer NonceDirection = 0
	// DirServerToClient marks frames sent by the server.
	DirServerToClient NonceDirection = 1
)

const (
	nonceSize = chacha20poly1305.NonceSize // 12
	keySize   = 32
	// DefaultReplayWindow is the anti-replay sliding window in sequence
	// numbers. Must stay >= the delivery-buffer window (design invariant).
	DefaultReplayWindow = 4096
)

// DeriveKey expands the shared PSK into the 32-byte channel key using
// HKDF-SHA256 with a fixed salt and info string.
func DeriveKey(psk []byte) ([]byte, error) {
	if len(psk) == 0 {
		return nil, errors.New("crypto: empty PSK")
	}
	salt := []byte("flexbraid-v1")
	info := []byte("channel-key")
	prk := hmacSHA256(salt, psk)
	return hkdfExpand(prk, info, keySize), nil
}

func hmacSHA256(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

func hkdfExpand(prk, info []byte, n int) []byte {
	out := make([]byte, 0, n)
	var t []byte
	for counter := byte(1); len(out) < n; counter++ {
		m := hmac.New(sha256.New, prk)
		m.Write(t)
		m.Write(info)
		m.Write([]byte{counter})
		t = m.Sum(nil)
		out = append(out, t...)
	}
	return out[:n]
}

// NewAEAD builds the AEAD cipher for the given cipher name
// ("chacha20poly1305" default, or "aes256gcm").
func NewAEAD(key []byte, name string) (cipher.AEAD, error) {
	if len(key) != keySize {
		return nil, fmt.Errorf("crypto: key must be %d bytes, got %d", keySize, len(key))
	}
	switch name {
	case "", "chacha20poly1305":
		return chacha20poly1305.New(key)
	case "aes256gcm":
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	default:
		return nil, fmt.Errorf("crypto: unknown cipher %q", name)
	}
}

// makeNonce builds the 12-byte nonce for a (direction, seq) pair. The seq is
// unique per direction for the lifetime of the key, so the nonce never
// repeats.
func makeNonce(dir NonceDirection, seq uint32) [nonceSize]byte {
	var n [nonceSize]byte
	n[4] = byte(dir)
	binary.BigEndian.PutUint32(n[8:], seq)
	return n
}

// frameSeq extracts the sequence number from a frame header (offset 16).
func frameSeq(header []byte) uint32 {
	return binary.BigEndian.Uint32(header[16:])
}

// Seal authenticates the frame header and encrypts the payload, returning the
// sealed frame: header(28) + ciphertext + tag(16). The input is the plaintext
// frame produced by frame.Frame.Encode (header + payload).
func Seal(aead cipher.AEAD, dir NonceDirection, plaintext []byte) ([]byte, error) {
	if len(plaintext) < 28 {
		return nil, errors.New("crypto: frame too short to seal")
	}
	header := plaintext[:28]
	payload := plaintext[28:]
	nonce := makeNonce(dir, frameSeq(header))
	sealed := aead.Seal(nil, nonce[:], payload, header)
	out := make([]byte, 0, len(header)+len(sealed))
	out = append(out, header...)
	out = append(out, sealed...)
	return out, nil
}

// Open authenticates and decrypts a sealed frame, returning the plaintext
// frame (header + payload) ready for frame.Decode. It fails on tampering,
// wrong key, or a direction/seq mismatch.
func Open(aead cipher.AEAD, dir NonceDirection, sealed []byte) ([]byte, error) {
	if len(sealed) < 28+aead.Overhead() {
		return nil, errors.New("crypto: sealed frame too short")
	}
	header := sealed[:28]
	body := sealed[28:]
	nonce := makeNonce(dir, frameSeq(header))
	payload, err := aead.Open(nil, nonce[:], body, header)
	if err != nil {
		return nil, errors.New("crypto: authentication failed")
	}
	out := make([]byte, 0, len(header)+len(payload))
	out = append(out, header...)
	out = append(out, payload...)
	return out, nil
}

// ReplayWindow is a sliding-window anti-replay filter (bitmap). It accepts a
// seq exactly once and rejects older or replayed seqs. The window size must
// be >= the delivery-buffer window so multi-path reordering is never treated
// as a replay (design invariant).
type ReplayWindow struct {
	window uint32
	base   uint32 // seq mapped to bit 0
	bits   []uint64
}

// NewReplayWindow creates a window of the given size (0 disables filtering,
// not recommended).
func NewReplayWindow(size uint32) *ReplayWindow {
	if size == 0 {
		size = DefaultReplayWindow
	}
	return &ReplayWindow{
		window: size,
		bits:   make([]uint64, (int(size)+63)/64),
	}
}

// CheckAndMark reports whether seq is new (not a replay) and marks it seen.
func (w *ReplayWindow) CheckAndMark(seq uint32) bool {
	diff := int64(seq) - int64(w.base)
	switch {
	case diff < 0:
		return false // older than the window base
	case diff >= int64(w.window):
		// seq is ahead of the window: slide the window forward.
		shift := uint64(diff - int64(w.window) + 1)
		w.shiftRight(shift)
		w.base = seq - w.window + 1
		diff = int64(w.window) - 1
	}
	bit := uint64(diff)
	mask := uint64(1) << (bit % 64)
	if w.bits[bit/64]&mask != 0 {
		return false // replay
	}
	w.bits[bit/64] |= mask
	return true
}

// shiftRight drops the lowest n bits (older seqs) by shifting the bitmap
// toward bit 0.
func (w *ReplayWindow) shiftRight(n uint64) {
	words := len(w.bits)
	wordShift := int(n / 64)
	bitShift := n % 64
	if wordShift >= words {
		clear(w.bits)
		return
	}
	for i := 0; i < words; i++ {
		var v uint64
		if src := i + wordShift; src < words {
			v = w.bits[src] >> bitShift
			if bitShift != 0 && src+1 < words {
				v |= w.bits[src+1] << (64 - bitShift)
			}
		}
		w.bits[i] = v
	}
}
