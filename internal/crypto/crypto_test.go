package crypto

import (
	"bytes"
	"testing"
)

func TestDeriveKeyDeterministic(t *testing.T) {
	k1, _ := DeriveKey([]byte("same"))
	k2, _ := DeriveKey([]byte("same"))
	k3, _ := DeriveKey([]byte("other"))
	if !bytes.Equal(k1, k2) {
		t.Error("same PSK must derive same key")
	}
	if bytes.Equal(k1, k3) {
		t.Error("different PSK must derive different key")
	}
	if _, err := DeriveKey(nil); err == nil {
		t.Error("empty PSK must error")
	}
}

func TestDeriveSessionKeyDistinctAndDeterministic(t *testing.T) {
	psk := []byte("test-psk")
	base, err := DeriveKey(psk)
	if err != nil {
		t.Fatalf("derive base: %v", err)
	}
	k1a := DeriveSessionKey(psk, 1)
	k1b := DeriveSessionKey(psk, 1)
	k2 := DeriveSessionKey(psk, 2)

	if !bytes.Equal(k1a, k1b) {
		t.Fatal("session key must be deterministic for the same session ID")
	}
	if bytes.Equal(k1a, k2) {
		t.Fatal("different session IDs must yield different keys")
	}
	if bytes.Equal(k1a, base) {
		t.Fatal("session key must differ from the base key")
	}
}

func TestSealOpenRoundTrip(t *testing.T) {
	key, _ := DeriveKey([]byte("psk"))
	aead, _ := NewAEAD(key, "chacha20poly1305")
	plain := make([]byte, 28)
	plain[16], plain[17], plain[18], plain[19] = 0, 0, 0, 7
	plain = append(plain, []byte("payload-data")...)
	sealed, err := Seal(aead, DirClientToServer, plain)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if len(sealed) != len(plain)+16 {
		t.Fatalf("sealed size = %d, want %d", len(sealed), len(plain)+16)
	}
	opened, err := Open(aead, DirClientToServer, sealed)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if !bytes.Equal(opened, plain) {
		t.Error("roundtrip mismatch")
	}
}

func TestOpenRejectsTamperedPayload(t *testing.T) {
	key, _ := DeriveKey([]byte("psk"))
	aead, _ := NewAEAD(key, "chacha20poly1305")
	plain := append(make([]byte, 28), []byte("payload")...)
	sealed, _ := Seal(aead, DirClientToServer, plain)
	sealed[len(sealed)-5] ^= 0xFF
	if _, err := Open(aead, DirClientToServer, sealed); err == nil {
		t.Error("tampered payload must fail auth")
	}
}

func TestOpenRejectsTamperedHeader(t *testing.T) {
	key, _ := DeriveKey([]byte("psk"))
	aead, _ := NewAEAD(key, "chacha20poly1305")
	plain := append(make([]byte, 28), []byte("payload")...)
	sealed, _ := Seal(aead, DirClientToServer, plain)
	sealed[5] ^= 0xFF // flags byte is authenticated
	if _, err := Open(aead, DirClientToServer, sealed); err == nil {
		t.Error("tampered header must fail auth")
	}
}

func TestOpenRejectsWrongKey(t *testing.T) {
	k1, _ := DeriveKey([]byte("psk-a"))
	k2, _ := DeriveKey([]byte("psk-b"))
	a1, _ := NewAEAD(k1, "chacha20poly1305")
	a2, _ := NewAEAD(k2, "chacha20poly1305")
	plain := append(make([]byte, 28), []byte("payload")...)
	sealed, _ := Seal(a1, DirClientToServer, plain)
	if _, err := Open(a2, DirClientToServer, sealed); err == nil {
		t.Error("wrong key must fail")
	}
}

func TestOpenRejectsWrongDirection(t *testing.T) {
	key, _ := DeriveKey([]byte("psk"))
	aead, _ := NewAEAD(key, "chacha20poly1305")
	plain := append(make([]byte, 28), []byte("payload")...)
	sealed, _ := Seal(aead, DirClientToServer, plain)
	if _, err := Open(aead, DirServerToClient, sealed); err == nil {
		t.Error("wrong direction must fail (nonce differs)")
	}
}

func TestOpenRejectsShortFrame(t *testing.T) {
	key, _ := DeriveKey([]byte("psk"))
	aead, _ := NewAEAD(key, "chacha20poly1305")
	if _, err := Open(aead, DirClientToServer, make([]byte, 10)); err == nil {
		t.Error("short frame must fail")
	}
}

func TestReplayWindow(t *testing.T) {
	w := NewReplayWindow(64)
	// fresh seqs accepted
	for i := uint32(1); i <= 10; i++ {
		if !w.CheckAndMark(i) {
			t.Fatalf("seq %d should be accepted", i)
		}
	}
	// replays rejected
	if w.CheckAndMark(5) {
		t.Error("replay of seq 5 must be rejected")
	}
	// old seq (below base) rejected after window advance
	if !w.CheckAndMark(100) { // advances base to 37
		t.Error("seq 100 should be accepted")
	}
	if w.CheckAndMark(10) {
		t.Error("seq 10 is below the window base, must be rejected")
	}
	// far-ahead seq slides the window and is accepted
	if !w.CheckAndMark(10000) {
		t.Error("far-ahead seq must be accepted")
	}
	// everything before the new base is rejected
	if w.CheckAndMark(100) {
		t.Error("seq 100 is now below the base, must be rejected")
	}
	// seq just inside the new window is accepted once
	if !w.CheckAndMark(9990) {
		t.Error("seq inside the new window must be accepted")
	}
	if w.CheckAndMark(9990) {
		t.Error("duplicate inside window must be rejected")
	}
}
