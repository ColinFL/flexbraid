// Forward-secrecy key exchange (M5.5, docs/DESIGN.md §11).
//
// The PSK is demoted to an *authenticator*: it only signs/verifies the
// handshake. The actual per-session AEAD key is derived from an ephemeral
// X25519 ECDH shared secret (perfect forward secrecy) mixed with the PSK
// (authentication binding) and the session ID:
//
//	shared    = X25519(client_ephemeral, server_ephemeral)
//	session    = HKDF(shared, psk as salt, "pfs-session:<id>")
//
// Because both ephemeral keys are discarded when the process exits, a later
// PSK compromise cannot decrypt past sessions (the ECDH secrets are gone).
// The key exchange rides the existing FIRST/ACK handshake frames: the FIRST
// request carries the client's ephemeral public key, the ACK carries the
// server's, both sealed under the PSK-derived *base* key.
package crypto

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// x25519 is the curve used for the ephemeral key exchange.
var x25519 = ecdh.X25519()

// PublicKeySize is the size of an X25519 public key (32 bytes).
const PublicKeySize = 32

// GenerateEphemeralKey returns a fresh X25519 ephemeral keypair. Private key
// must never leave the process; public key is sent encrypted inside the
// handshake.
func GenerateEphemeralKey() (priv, pub []byte, err error) {
	k, err := x25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return k.Bytes(), k.PublicKey().Bytes(), nil
}

// ECDHShared computes the X25519 shared secret between our ephemeral private
// key and the peer's ephemeral public key.
func ECDHShared(priv, peerPub []byte) ([]byte, error) {
	if len(priv) != PublicKeySize {
		return nil, errors.New("crypto: private key must be 32 bytes")
	}
	if len(peerPub) != PublicKeySize {
		return nil, errors.New("crypto: peer public key must be 32 bytes")
	}
	privKey, err := x25519.NewPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pubKey, err := x25519.NewPublicKey(peerPub)
	if err != nil {
		return nil, err
	}
	return privKey.ECDH(pubKey)
}

// DerivePFSKey derives the per-session AEAD key from the ECDH shared secret
// (forward secrecy) with the PSK as the HKDF salt (authentication: only a
// party holding the PSK can construct the same base key) and the session ID
// in the info string (session isolation). 32 bytes out.
func DerivePFSKey(psk, shared []byte, sessionID uint64) []byte {
	info := make([]byte, 0, 16)
	info = append(info, "pfs-session:"...)
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], sessionID)
	info = append(info, b[:]...)
	return derive(shared, string(psk), string(info))
}
