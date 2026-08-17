package fec

import (
	"math"
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

// TestMixedFECModes: an FEC decoder must handle a sender whose FEC is
// disabled — frames with block_seq=0 carry no block structure and are
// delivered immediately (the lastFlushed guard would otherwise drop them
// as "already delivered"). Conversely, a pass-through decoder must not
// leak parity frames into the inner stream.
func TestMixedFECModes(t *testing.T) {
	// 1) FEC-enabled decoder receiving an FEC-less sender's frames.
	params := Params{DataShards: 4, ParityShards: 1, BlockTimeout: 15 * time.Millisecond}
	dec, err := NewDecoder(params)
	if err != nil {
		t.Fatal(err)
	}
	f := &frame.Frame{SessionID: 1, Seq: 7, BlockSeq: 0, Payload: []byte("no-fec")}
	got := dec.Push("w1", f)
	if len(got) != 1 || got[0].Seq != 7 {
		t.Fatalf("FEC-off sender frame must be delivered immediately, got %d frames", len(got))
	}

	// 2) Pass-through (FEC-disabled) decoder receiving a parity frame
	// from an FEC-enabled sender: must drop it, not leak it.
	dec2, err := NewDecoder(Params{BlockTimeout: 15 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	pf := &frame.Frame{SessionID: 1, Seq: 8, BlockSeq: 2, Payload: []byte("parity"),
		Flags: frame.FlagFECParity}
	if got := dec2.Push("w1", pf); len(got) != 0 {
		t.Fatalf("pass-through decoder must drop parity frames, got %d", len(got))
	}
	df := &frame.Frame{SessionID: 1, Seq: 9, BlockSeq: 2, Payload: []byte("data")}
	if got := dec2.Push("w1", df); len(got) != 1 {
		t.Fatalf("pass-through decoder must deliver data frames, got %d", len(got))
	}
}

// TestAdaptivePassThroughWhenClean: with no loss the adaptive encoder must
// not code at all — frames pass through immediately with block_seq=0.
func TestAdaptivePassThroughWhenClean(t *testing.T) {
	enc, err := NewEncoder(adaptiveTestParams(0))
	if err != nil {
		t.Fatal(err)
	}
	f := &frame.Frame{SessionID: testSession, Seq: 1, Payload: []byte("x")}
	out := enc.Push(f)
	if len(out) != 1 || out[0] != f {
		t.Fatalf("clean link: frame must pass through immediately")
	}
	if f.BlockSeq != 0 {
		t.Fatalf("pass-through frame must carry block_seq=0, got %d", f.BlockSeq)
	}
}

// TestAdaptiveCodingOnLoss: when the measured loss crosses the on-threshold
// the encoder starts coding: blocks fill to k and parity frames fly.
func TestAdaptiveCodingOnLoss(t *testing.T) {
	enc, err := NewEncoder(adaptiveTestParams(0.05)) // 5% loss → coding
	if err != nil {
		t.Fatal(err)
	}
	enc.SetLossRate(0.05)

	var out []*frame.Frame
	for i := 1; i <= 4; i++ { // k=4
		f := &frame.Frame{SessionID: testSession, Seq: uint32(i), Payload: []byte{byte(i)}}
		out = append(out, enc.Push(f)...)
	}
	if len(out) < 4 {
		t.Fatalf("coded block must emit >= k frames, got %d", len(out))
	}
	parity := 0
	for _, f := range out {
		if f.HasFlag(frame.FlagFECParity) {
			parity++
		}
	}
	if parity == 0 {
		t.Fatal("coded block must carry parity frames")
	}
}

// TestAdaptiveHysteresis: once coding turns on it holds for Hold even if
// the loss drops; only after Hold expires below the resume threshold does
// the encoder return to pass-through.
func TestAdaptiveHysteresis(t *testing.T) {
	params := adaptiveTestParams(0)
	params.Adaptive.Hold = time.Second
	enc, err := NewEncoder(params)
	if err != nil {
		t.Fatal(err)
	}
	// Turn coding on.
	enc.SetLossRate(0.05)
	// Loss disappears, but the hold window is still open → stays coding.
	enc.SetLossRate(0)
	f1 := &frame.Frame{SessionID: testSession, Seq: 1, Payload: []byte("x")}
	if out := enc.Push(f1); len(out) != 0 {
		t.Fatal("must still be coding during the hold window")
	}
	// Let the hold window expire, then re-evaluate with clean loss.
	time.Sleep(1100 * time.Millisecond)
	enc.SetLossRate(0)
	f2 := &frame.Frame{SessionID: testSession, Seq: 2, Payload: []byte("y")}
	out := enc.Push(f2)
	// The frame buffered during coding flushes too — both pass-through.
	if len(out) != 2 {
		t.Fatalf("after hold expiry must flush pending + new frame pass-through, got %d", len(out))
	}
	for _, got := range out {
		if got.BlockSeq != 0 {
			t.Fatalf("post-hold frames must be pass-through (block_seq=0), got %d", got.BlockSeq)
		}
	}
}

// TestAdaptiveParityScalesWithLoss: more loss → more redundancy (up to the
// ceiling).
func TestAdaptiveParityScalesWithLoss(t *testing.T) {
	enc, err := NewEncoder(adaptiveTestParams(0.5))
	if err != nil {
		t.Fatal(err)
	}
	enc.SetLossRate(0.02)
	low := enc.parityForLoss(0.02)
	enc.SetLossRate(0.30)
	high := enc.parityForLoss(0.30)
	if high <= low {
		t.Fatalf("parity must scale with loss: low=%d high=%d", low, high)
	}
	if enc.parityForLoss(0.5) > enc.params.ParityShards {
		t.Fatal("parity must never exceed the configured ceiling")
	}
}

// TestAdaptiveTransitionFlushesPending: frames buffered during a coding
// period are flushed (un-stamped) when the encoder drops back to
// pass-through — they must not wait for the block timeout.
func TestAdaptiveTransitionFlushesPending(t *testing.T) {
	params := adaptiveTestParams(0)
	params.Adaptive.Hold = 0
	enc, err := NewEncoder(params)
	if err != nil {
		t.Fatal(err)
	}
	enc.SetLossRate(0.05) // coding on
	// Fill 2 of k=4 frames (block not complete).
	for i := 1; i <= 2; i++ {
		f := &frame.Frame{SessionID: testSession, Seq: uint32(i), Payload: []byte{byte(i)}}
		if out := enc.Push(f); len(out) != 0 {
			t.Fatalf("partial block must not emit")
		}
	}
	// Loss drops → pass-through: the 2 pending frames must come out at once.
	enc.SetLossRate(0)
	f := &frame.Frame{SessionID: testSession, Seq: 3, Payload: []byte{3}}
	out := enc.Push(f)
	if len(out) != 3 {
		t.Fatalf("transition must flush 2 pending + 1 new frame, got %d", len(out))
	}
	for _, got := range out {
		if got.BlockSeq != 0 {
			t.Fatalf("flushed frames must be pass-through (block_seq=0), got %d", got.BlockSeq)
		}
	}
}

// adaptiveTestParams builds adaptive codec params: k=4, ceiling 50% loss,
// on-threshold 2%, resume 0.5%. The parity ceiling is never 0 (a 0-ceiling
// codec would be disabled entirely).
func adaptiveTestParams(loss float64) Params {
	p := int(math.Ceil(4 * loss / (1 - loss)))
	if p < 1 {
		p = 1
	}
	return Params{
		DataShards:   4,
		ParityShards: p,
		BlockTimeout: 8 * time.Millisecond,
		Adaptive: &AdaptiveParams{
			OnLossPct:  2,
			OffLossPct: 0.5,
			Hold:       0,
			MaxLossPct: 50,
			Safety:     1.3,
		},
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
