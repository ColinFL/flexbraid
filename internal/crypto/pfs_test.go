package crypto

// PFS key-exchange tests (M5.5): both sides arrive at the same session key,
// wrong-identity peers arrive at different keys, and the shared secret
// differs between sessions (forward secrecy).

import (
	"bytes"
	"testing"
)

func mustKeyPair(t *testing.T) (priv, pub []byte) {
	t.Helper()
	priv, pub, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatal(err)
	}
	return priv, pub
}

func TestPFSKeyAgreement(t *testing.T) {
	psk := []byte("a-shared-secret")
	cPriv, cPub := mustKeyPair(t)
	sPriv, sPub := mustKeyPair(t)

	cShared, err := ECDHShared(cPriv, sPub)
	if err != nil {
		t.Fatal(err)
	}
	sShared, err := ECDHShared(sPriv, cPub)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(cShared, sShared) {
		t.Fatal("ECDH shared secrets differ")
	}

	cKey := DerivePFSKey(psk, cShared, 7)
	sKey := DerivePFSKey(psk, sShared, 7)
	if !bytes.Equal(cKey, sKey) {
		t.Fatal("session keys differ between sides")
	}
	if len(cKey) != keySize {
		t.Fatalf("session key size = %d, want %d", len(cKey), keySize)
	}
}

func TestPFSForwardSecrecy(t *testing.T) {
	psk := []byte("psk")
	// Two distinct sessions (fresh ephemerals) must get distinct keys.
	_, c1Pub := mustKeyPair(t)
	s1Priv, _ := mustKeyPair(t)
	_, c2Pub := mustKeyPair(t)
	s2Priv, _ := mustKeyPair(t)

	share1, _ := ECDHShared(s1Priv, c1Pub)
	share2, _ := ECDHShared(s2Priv, c2Pub)
	key1 := DerivePFSKey(psk, share1, 1)
	key2 := DerivePFSKey(psk, share2, 2)
	if bytes.Equal(key1, key2) {
		t.Fatal("session keys must differ across sessions")
	}
}

func TestPFSWrongPair(t *testing.T) {
	psk := []byte("psk")
	_, cPub := mustKeyPair(t)
	sPriv, _ := mustKeyPair(t)
	otherPriv, _ := mustKeyPair(t)

	// A MITM that exchanged its own ephemeral keys but lacks the peer's
	// private key agrees on a different shared secret — and therefore a
	// different session key — than the genuine peer.
	realShared, _ := ECDHShared(sPriv, cPub)
	mitmShared, _ := ECDHShared(otherPriv, cPub) // attacker's ephemeral vs client pub
	if bytes.Equal(realShared, mitmShared) {
		t.Fatal("MITM-derived shared secret must differ")
	}
	realKey := DerivePFSKey(psk, realShared, 42)
	mitmKey := DerivePFSKey(psk, mitmShared, 42)
	if bytes.Equal(realKey, mitmKey) {
		t.Fatal("MITM-derived session key must differ")
	}
}

func TestPFSKeySizeValidation(t *testing.T) {
	priv, _, _ := GenerateEphemeralKey()
	if _, err := ECDHShared(priv, make([]byte, 16)); err == nil {
		t.Fatal("short peer pub should error")
	}
}
