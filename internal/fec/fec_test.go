package fec

import (
	"math/rand"
	"testing"
	"time"

	"github.com/ColinFL/flexbraid/internal/frame"
)

const (
	testSession = 42
	testK       = 10
	testParity  = 4
)

func testParams() Params {
	return Params{DataShards: testK, ParityShards: testParity, BlockTimeout: 8 * time.Millisecond}
}

// makeDataFrames builds k frames with seqs 1..k and distinct payload sizes.
func makeDataFrames(k int) []*frame.Frame {
	out := make([]*frame.Frame, k)
	for i := 0; i < k; i++ {
		payload := make([]byte, (i*7)%50+1) // 1..50 bytes, varying
		for j := range payload {
			payload[j] = byte(i*3 + j)
		}
		out[i] = &frame.Frame{
			SessionID: testSession,
			Seq:       uint32(i + 1),
			Payload:   payload,
		}
	}
	return out
}

// encodeAll runs frames through the encoder and returns emitted frames.
func encodeAll(t *testing.T, enc *Encoder, frames []*frame.Frame) []*frame.Frame {
	t.Helper()
	var out []*frame.Frame
	for _, f := range frames {
		out = append(out, enc.Push(f)...)
	}
	if len(out) == 0 {
		t.Fatal("encoder emitted nothing")
	}
	return out
}

// decodeAll feeds emitted frames to the decoder, ticking once the timeout
// passes, and returns delivered data frames.
func decodeAll(t *testing.T, dec *Decoder, emitted []*frame.Frame) []*frame.Frame {
	t.Helper()
	var delivered []*frame.Frame
	for _, f := range emitted {
		delivered = append(delivered, dec.Push("test", f)...)
	}
	delivered = append(delivered, dec.Tick(time.Now().Add(100*time.Millisecond))...)
	return delivered
}

func assertDelivered(t *testing.T, delivered []*frame.Frame, wantSeq []uint32) {
	t.Helper()
	if len(delivered) != len(wantSeq) {
		t.Fatalf("want %d delivered, got %d: %+v", len(wantSeq), len(delivered), delivered)
	}
	for i, f := range delivered {
		if f.Seq != wantSeq[i] {
			t.Fatalf("delivered seq %d, want %d (order)", f.Seq, wantSeq[i])
		}
	}
}

// TestTakeStreamStats: the decoder accounts unrecovered loss per stream —
// data frames missing when a block flushes. Recovered blocks count zero.
func TestTakeStreamStats(t *testing.T) {
	params := Params{DataShards: 2, ParityShards: 1, BlockTimeout: 8 * time.Millisecond}
	enc, err := NewEncoder(params)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewDecoder(params)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()

	// Block 1: deliver data1 + parity (data2 lost on the wire) → RS
	// reconstructs, so NOTHING is counted as lost.
	f1 := &frame.Frame{SessionID: testSession, Seq: 1, Payload: []byte("a")}
	f2 := &frame.Frame{SessionID: testSession, Seq: 2, Payload: []byte("bb")}
	emitted := encodeAll(t, enc, []*frame.Frame{f1, f2}) // data1, data2, parity
	var parity *frame.Frame
	for _, f := range emitted {
		if f.HasFlag(frame.FlagFECParity) {
			parity = f
		}
	}
	if parity == nil {
		t.Fatal("no parity emitted")
	}
	delivered := dec.Push("path", f1)
	delivered = append(delivered, dec.Push("path", parity)...)
	if len(delivered) != 2 {
		t.Fatalf("reconstruction must deliver both frames, got %d", len(delivered))
	}
	lost, received := dec.TakeStreamStats(testSession, "path")
	if lost != 0 || received != 1 {
		t.Fatalf("recovered block: want lost=0 received=1, got lost=%d received=%d", lost, received)
	}

	// Block 2: both data frames lost, only the parity arrives → nothing
	// to reconstruct; flush at deadline counts 2 lost.
	f3 := &frame.Frame{SessionID: testSession, Seq: 3, Payload: []byte("ccc")}
	f4 := &frame.Frame{SessionID: testSession, Seq: 4, Payload: []byte("dddd")}
	emitted = encodeAll(t, enc, []*frame.Frame{f3, f4})
	parity = nil
	for _, f := range emitted {
		if f.HasFlag(frame.FlagFECParity) {
			parity = f
		}
	}
	if parity == nil {
		t.Fatal("no parity emitted")
	}
	if out := dec.Push("path", parity); len(out) != 0 {
		t.Fatalf("single parity shard must not deliver yet: %d", len(out))
	}
	dec.Tick(now.Add(100 * time.Millisecond)) // block deadline passes
	lost, received = dec.TakeStreamStats(testSession, "path")
	if lost != 2 || received != 0 {
		t.Fatalf("lost block: want lost=2 received=0, got lost=%d received=%d", lost, received)
	}
}

// findSeq returns the index of the frame with seq, or -1.
func findSeq(frames []*frame.Frame, seq uint32) int {
	for i, f := range frames {
		if f.Seq == seq {
			return i
		}
	}
	return -1
}

func TestRoundTripNoLoss(t *testing.T) {
	enc, _ := NewEncoder(testParams())
	dec, _ := NewDecoder(testParams())

	data := makeDataFrames(testK)
	emitted := encodeAll(t, enc, data)
	// 10 data + 4 parity.
	if len(emitted) != testK+testParity {
		t.Fatalf("want %d frames, got %d", testK+testParity, len(emitted))
	}
	delivered := decodeAll(t, dec, emitted)

	seqs := make([]uint32, testK)
	for i := range seqs {
		seqs[i] = uint32(i + 1)
	}
	assertDelivered(t, delivered, seqs)
	for i, f := range delivered {
		if string(f.Payload) != string(data[i].Payload) {
			t.Fatalf("payload mismatch at %d", i)
		}
	}
}

func TestRecoverLostDataAndParity(t *testing.T) {
	enc, _ := NewEncoder(testParams())
	dec, _ := NewDecoder(testParams())

	data := makeDataFrames(testK)
	emitted := encodeAll(t, enc, data)

	// Drop 2 data frames (seqs 3, 7) and 1 parity frame: 3 losses, 4 parity.
	drop := map[int]bool{2: true, 6: true, testK + 1: true}
	var wire []*frame.Frame
	for i, f := range emitted {
		if !drop[i] {
			wire = append(wire, f)
		}
	}
	delivered := decodeAll(t, dec, wire)

	seqs := make([]uint32, testK)
	for i := range seqs {
		seqs[i] = uint32(i + 1)
	}
	assertDelivered(t, delivered, seqs)
	// Reconstructed payloads must be byte-exact.
	for i, f := range delivered {
		if string(f.Payload) != string(data[i].Payload) {
			t.Fatalf("reconstructed payload mismatch at seq %d", f.Seq)
		}
	}
}

func TestTooMuchLossDeliversPartialOnTimeout(t *testing.T) {
	enc, _ := NewEncoder(testParams())
	dec, _ := NewDecoder(testParams())

	data := makeDataFrames(testK)
	emitted := encodeAll(t, enc, data)

	// Drop everything except the first 3 data frames: 7 losses > 4 parity.
	var wire []*frame.Frame
	for i := 0; i < 3; i++ {
		wire = append(wire, emitted[i])
	}
	delivered := decodeAll(t, dec, wire)
	assertDelivered(t, delivered, []uint32{1, 2, 3})
}

func TestVariablePayloadSizesRecoverExact(t *testing.T) {
	enc, _ := NewEncoder(testParams())
	dec, _ := NewDecoder(testParams())

	data := makeDataFrames(testK)
	// Make the longest frame the one we will drop, to prove max_len is
	// carried in the sub-header (not inferred from received frames).
	data[5].Payload = make([]byte, 1200)
	for i := range data[5].Payload {
		data[5].Payload[i] = 0xAB
	}
	emitted := encodeAll(t, enc, data)

	var wire []*frame.Frame
	for i, f := range emitted {
		if i != 5 { // drop the 1200-byte frame
			wire = append(wire, f)
		}
	}
	delivered := decodeAll(t, dec, wire)

	if len(delivered) != testK {
		t.Fatalf("want %d delivered, got %d", testK, len(delivered))
	}
	if string(delivered[5].Payload) != string(data[5].Payload) {
		t.Fatalf("reconstructed long payload mismatch (len %d != %d)",
			len(delivered[5].Payload), len(data[5].Payload))
	}
}

func TestOutOfOrderArrival(t *testing.T) {
	enc, _ := NewEncoder(testParams())
	dec, _ := NewDecoder(testParams())

	data := makeDataFrames(testK)
	emitted := encodeAll(t, enc, data)

	// Reverse the wire order; the decoder must still emit in seq order.
	rng := rand.New(rand.NewSource(7))
	wire := append([]*frame.Frame{}, emitted...)
	rng.Shuffle(len(wire), func(i, j int) { wire[i], wire[j] = wire[j], wire[i] })

	delivered := decodeAll(t, dec, wire)
	seqs := make([]uint32, testK)
	for i := range seqs {
		seqs[i] = uint32(i + 1)
	}
	assertDelivered(t, delivered, seqs)
}

func TestShortBlockFlushedOnTimeout(t *testing.T) {
	params := Params{DataShards: testK, ParityShards: testParity, BlockTimeout: 5 * time.Millisecond}
	enc, _ := NewEncoder(params)
	dec, _ := NewDecoder(params)

	// Only 3 frames arrive before the timeout.
	data := makeDataFrames(3)
	var emitted []*frame.Frame
	for _, f := range data {
		emitted = append(emitted, enc.Push(f)...)
	}
	if len(emitted) != 0 {
		t.Fatal("encoder must not emit before k frames or timeout")
	}
	emitted = append(emitted, enc.Tick(time.Now().Add(10*time.Millisecond))...)
	if len(emitted) != 3 {
		t.Fatalf("short block must flush 3 frames without parity, got %d", len(emitted))
	}
	for _, f := range emitted {
		if f.HasFlag(frame.FlagFECParity) {
			t.Fatal("short block must not contain parity frames")
		}
	}

	delivered := decodeAll(t, dec, emitted)
	assertDelivered(t, delivered, []uint32{1, 2, 3})
}

func TestDisabledParamsPassThrough(t *testing.T) {
	enc, _ := NewEncoder(Params{BlockTimeout: time.Millisecond})
	dec, _ := NewDecoder(Params{BlockTimeout: time.Millisecond})

	f := &frame.Frame{SessionID: testSession, Seq: 9, Payload: []byte("x")}
	out := enc.Push(f)
	if len(out) != 1 || out[0] != f {
		t.Fatal("disabled encoder must pass the frame straight through")
	}
	got := dec.Push("test", f)
	if len(got) != 1 || got[0] != f {
		t.Fatal("disabled decoder must pass the frame straight through")
	}
	if enc.Tick(time.Now()) != nil || dec.Tick(time.Now()) != nil {
		t.Fatal("disabled codecs must not tick anything")
	}
}

func TestParitySubHeaderSelfDescribes(t *testing.T) {
	enc, _ := NewEncoder(testParams())
	data := makeDataFrames(testK)
	emitted := encodeAll(t, enc, data)

	// Inspect the first parity frame's sub-header.
	pf := emitted[testK]
	if !pf.HasFlag(frame.FlagFECParity) {
		t.Fatalf("frame %d must be parity", testK)
	}
	st := &blockState{}
	if err := (&Decoder{}).addParity(st, pf); err != nil {
		t.Fatalf("sub-header parse: %v", err)
	}
	if st.k != testK {
		t.Errorf("parsed k = %d, want %d", st.k, testK)
	}
	if len(st.seqs) != testK {
		t.Fatalf("parsed %d data seqs, want %d", len(st.seqs), testK)
	}
	for i, seq := range st.seqs {
		if seq != uint32(i+1) {
			t.Errorf("seq[%d] = %d, want %d", i, seq, i+1)
		}
	}
	// maxLen must equal the largest data payload.
	wantMax := 0
	for _, f := range data {
		if len(f.Payload) > wantMax {
			wantMax = len(f.Payload)
		}
	}
	if st.maxLen != wantMax {
		t.Errorf("parsed max_len = %d, want %d", st.maxLen, wantMax)
	}
	if len(st.parity) != 1 || st.parity[0] == nil {
		t.Error("parity shard not stored")
	}
}
