package frame

import (
	"bytes"
	"testing"
)

func testFrame() *Frame {
	return &Frame{
		Flags:     FlagFirst,
		SessionID: 0xDEADBEEFCAFEBABE,
		Seq:       42,
		BlockSeq:  7,
		Payload:   []byte("hello flexbraid"),
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	f := testFrame()
	b, err := f.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if len(b) != HeaderSize+len(f.Payload) {
		t.Fatalf("encoded size = %d, want %d", len(b), HeaderSize+len(f.Payload))
	}
	got, err := Decode(b)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Version != Version || got.Flags != f.Flags || got.SessionID != f.SessionID ||
		got.Seq != f.Seq || got.BlockSeq != f.BlockSeq || !bytes.Equal(got.Payload, f.Payload) {
		t.Errorf("roundtrip mismatch:\n got %+v\nwant %+v", got, f)
	}
}

func TestDecodeHeader(t *testing.T) {
	f := testFrame()
	b, _ := f.Encode()
	h, err := DecodeHeader(b)
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if h.SessionID != f.SessionID || h.Seq != f.Seq || h.Flags != f.Flags {
		t.Errorf("header mismatch: %+v", h)
	}
	if h.Payload != nil {
		t.Errorf("DecodeHeader must not expose payload")
	}
}

func TestDecodeRejectsBadMagic(t *testing.T) {
	f := testFrame()
	b, _ := f.Encode()
	b[0] ^= 0xFF
	if _, err := DecodeHeader(b); err == nil {
		t.Error("expected error for bad magic")
	}
}

func TestDecodeRejectsShortFrame(t *testing.T) {
	if _, err := DecodeHeader(make([]byte, 10)); err == nil {
		t.Error("expected error for short frame")
	}
}

func TestDecodeRejectsLengthMismatch(t *testing.T) {
	f := testFrame()
	b, _ := f.Encode()
	if _, err := Decode(b[:len(b)-1]); err == nil {
		t.Error("expected error for truncated payload")
	}
}

func TestEncodeRejectsHugePayload(t *testing.T) {
	f := testFrame()
	f.Payload = make([]byte, MaxPayload+1)
	if _, err := f.Encode(); err == nil {
		t.Error("expected error for oversized payload")
	}
}

func TestHasFlag(t *testing.T) {
	f := &Frame{Flags: FlagFirst | FlagControl}
	if !f.HasFlag(FlagFirst) || !f.HasFlag(FlagControl) || f.HasFlag(FlagKeepalive) {
		t.Error("HasFlag misbehaves")
	}
}
