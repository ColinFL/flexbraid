// Package fec implements Reed–Solomon forward error correction for
// FlexBraid blocks (docs/PROTOCOL.md §4, docs/DESIGN.md §6).
//
// Blocks are constructed per WAN: k data frames + (n−k) parity frames, all
// carried on the same path, so within-path FEC is always coherent (design
// invariant §7.4). The decoder reconstructs a block as soon as it holds any
// k of its frames — data or parity.
//
// Key properties:
//   - parity frames are self-describing: their payload starts with a
//     sub-header carrying k, the parity index, the padded shard size, the
//     block's data seqs and the per-frame payload lengths. The decoder
//     therefore needs no parameter negotiation and can reconstruct exact
//     payload bytes.
//   - the encoder flushes a short block (fewer than k frames within
//     BlockTimeout) without parity; the decoder delivers it on its own
//     timeout. This bounds FEC latency for sparse traffic.
//   - Params{ParityShards: 0} disables coding: Push passes frames straight
//     through with no buffering and no block assignment.
//
// The codec is synchronous (Push/Tick return frames to send); the tunnel
// drives Tick from its own ticker, so no goroutines are spawned per codec.
package fec

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ColinFL/flexbraid/internal/frame"
	"github.com/klauspost/reedsolomon"
)

// DefaultDataShards is the fixed number of data frames per FEC block in M2.
const DefaultDataShards = 10

// Params describes a codec. ParityShards == 0 disables coding.
type Params struct {
	DataShards   int
	ParityShards int
	BlockTimeout time.Duration
}

// Enabled reports whether coding is active.
func (p Params) Enabled() bool { return p.ParityShards > 0 }

// parity sub-header layout (all big-endian), payload of a parity frame:
//
//	[0:2]   u16 k            — number of data frames in the block
//	[2:4]   u16 parity index — position of this shard in the parity list
//	[4:6]   u16 max_len      — padded shard size (bytes)
//	[6:6+4k]     k × u32     — data seqs of the block, in order
//	[6+4k:6+6k]  k × u16     — original payload length of each data frame
//	[6+6k:]       max_len    — the parity shard itself
const (
	parityHdrFixed = 6
)

// ParityHeaderSize returns the byte size of the self-describing parity
// sub-header for a codec with the given number of data shards. It is the
// FEC-specific headroom that must be subtracted from the inner MTU so that
// the largest parity frame still fits the path MTU (design §6.6).
func ParityHeaderSize(dataShards int) int {
	return parityHdrFixed + 4*dataShards + 2*dataShards
}

// Encoder turns data frames into FEC blocks. Safe for concurrent use
// (Push from the data loop, Tick from the tunnel's ticker).
type Encoder struct {
	mu     sync.Mutex
	params Params
	rs     reedsolomon.Encoder

	block      uint32 // next block_seq (per WAN, per direction)
	pending    []*frame.Frame
	blockStart time.Time
}

// NewEncoder builds an RS encoder for the given params.
func NewEncoder(p Params) (*Encoder, error) {
	if p.DataShards <= 0 {
		p.DataShards = DefaultDataShards
	}
	if p.BlockTimeout <= 0 {
		p.BlockTimeout = 8 * time.Millisecond
	}
	var rs reedsolomon.Encoder
	if p.Enabled() {
		var err error
		rs, err = reedsolomon.New(p.DataShards, p.ParityShards)
		if err != nil {
			return nil, fmt.Errorf("fec: rs.New(%d,%d): %w", p.DataShards, p.ParityShards, err)
		}
	}
	return &Encoder{params: p, rs: rs}, nil
}

// Params returns the codec parameters.
func (e *Encoder) Params() Params { return e.params }

// Push accepts a data frame and returns frames to transmit: nothing while a
// block is still filling, or the completed block (data + parity) once k data
// frames are collected. The returned frames must be stamped with their seq
// and session by the caller; parity frames copy the session of the first
// data frame in the block.
func (e *Encoder) Push(f *frame.Frame) []*frame.Frame {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.params.Enabled() {
		return []*frame.Frame{f}
	}
	if len(e.pending) == 0 {
		e.blockStart = time.Now()
	}
	e.pending = append(e.pending, f)
	if len(e.pending) < e.params.DataShards {
		return nil
	}
	return e.emitBlock()
}

// Tick flushes a short block whose fill time exceeded BlockTimeout. It
// returns nothing unless there is an overdue block with fewer than k frames.
// Call from the tunnel's ticker.
func (e *Encoder) Tick(now time.Time) []*frame.Frame {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.params.Enabled() || len(e.pending) == 0 {
		return nil
	}
	if now.Before(e.blockStart.Add(e.params.BlockTimeout)) {
		return nil
	}
	// Short block: emit the collected data frames without parity. The
	// decoder cannot reconstruct anything, but it must not wait forever.
	e.block++
	bs := e.block
	out := e.pending
	for _, f := range out {
		f.BlockSeq = bs
	}
	e.pending = nil
	return out
}

// emitBlock seals the current block: stamps block_seq on the data frames,
// computes parity and returns data frames followed by parity frames.
func (e *Encoder) emitBlock() []*frame.Frame {
	e.block++
	bs := e.block
	data := e.pending
	e.pending = nil

	maxLen := 0
	for _, f := range data {
		if len(f.Payload) > maxLen {
			maxLen = len(f.Payload)
		}
	}
	n := e.params.DataShards + e.params.ParityShards
	shards := make([][]byte, n)
	for i := 0; i < n; i++ {
		shards[i] = make([]byte, maxLen)
	}
	for i, f := range data {
		copy(shards[i], f.Payload)
	}
	// Reconstruct-style safety: Encode fills the parity shards.
	if err := e.rs.Encode(shards); err != nil {
		// Cannot happen for valid params; fall back to no coding.
		for _, f := range data {
			f.BlockSeq = bs
		}
		return data
	}

	out := make([]*frame.Frame, 0, len(data)+e.params.ParityShards)
	for _, f := range data {
		f.BlockSeq = bs
		out = append(out, f)
	}
	sub := make([]byte, ParityHeaderSize(e.params.DataShards)+maxLen)
	binary.BigEndian.PutUint16(sub[0:2], uint16(e.params.DataShards))
	for i, f := range data {
		binary.BigEndian.PutUint32(sub[parityHdrFixed+4*i:], f.Seq)
	}
	for i, f := range data {
		binary.BigEndian.PutUint16(sub[parityHdrFixed+4*e.params.DataShards+2*i:], uint16(len(f.Payload)))
	}
	binary.BigEndian.PutUint16(sub[4:6], uint16(maxLen))
	for i := 0; i < e.params.ParityShards; i++ {
		pf := &frame.Frame{
			SessionID: data[0].SessionID,
			BlockSeq:  bs,
			Flags:     frame.FlagFECParity,
		}
		binary.BigEndian.PutUint16(sub[2:4], uint16(i))
		copy(sub[ParityHeaderSize(e.params.DataShards):], shards[e.params.DataShards+i])
		pf.Payload = make([]byte, ParityHeaderSize(e.params.DataShards)+maxLen)
		copy(pf.Payload, sub)
		out = append(out, pf)
	}
	return out
}

// streamKey identifies one FEC stream: a session's frames on one path.
// Blocks are per-path (M3): two WANs of the same session have independent
// block sequences, so the decoder must never mix them.
type streamKey struct {
	sessionID uint64
	path      string
}

// blockKey identifies a FEC block within a stream.
type blockKey struct {
	sessionID uint64
	path      string
	blockSeq  uint32
}

// blockState is the decoder's per-block assembly buffer.
type blockState struct {
	k        int
	seqs     []uint32 // data seqs in order (from the first parity frame)
	lens     []uint16 // original payload lengths
	maxLen   int
	data     map[uint32][]byte // seq → payload
	parity   map[int][]byte    // parity index → shard
	deadline time.Time
	flushed  bool
}

// Decoder reassembles FEC blocks and emits data frames in seq order. Safe
// for concurrent use (Push from the data loop, Tick from the tunnel's
// ticker).
type Decoder struct {
	mu     sync.Mutex
	params Params
	rs     reedsolomon.Encoder
	blocks map[blockKey]*blockState
	// lastFlushed tracks the highest flushed block_seq per session so that
	// frames arriving after their block was delivered (reconstructed or
	// flushed on timeout) cannot create phantom blocks and duplicate
	// delivery.
	lastFlushed map[streamKey]uint32
}

// NewDecoder builds a decoder for the given params.
func NewDecoder(p Params) (*Decoder, error) {
	if p.DataShards <= 0 {
		p.DataShards = DefaultDataShards
	}
	if p.BlockTimeout <= 0 {
		p.BlockTimeout = 8 * time.Millisecond
	}
	var rs reedsolomon.Encoder
	if p.Enabled() {
		var err error
		rs, err = reedsolomon.New(p.DataShards, p.ParityShards)
		if err != nil {
			return nil, fmt.Errorf("fec: rs.New(%d,%d): %w", p.DataShards, p.ParityShards, err)
		}
	}
	return &Decoder{params: p, rs: rs, blocks: make(map[blockKey]*blockState),
		lastFlushed: make(map[streamKey]uint32)}, nil
}

// Push accepts a data or parity frame of a stream (session+path) and returns
// any data frames that can now be delivered (in seq order). Frames of an
// already-flushed block are dropped. The path identifies the WAN the frame
// arrived on (M3): blocks are per-path, so two WANs' block sequences never
// collide.
func (d *Decoder) Push(path string, f *frame.Frame) []*frame.Frame {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.params.Enabled() {
		return []*frame.Frame{f}
	}
	key := blockKey{sessionID: f.SessionID, path: path, blockSeq: f.BlockSeq}
	st := d.blocks[key]
	if st == nil {
		sk := streamKey{sessionID: f.SessionID, path: path}
		if d.lastFlushed[sk] >= key.blockSeq {
			return nil // block already delivered; late/duplicate frame
		}
		st = &blockState{
			data:   make(map[uint32][]byte),
			parity: make(map[int][]byte),
		}
		d.blocks[key] = st
	}
	if st.flushed {
		return nil
	}

	if f.HasFlag(frame.FlagFECParity) {
		if err := d.addParity(st, f); err != nil {
			return nil
		}
	} else {
		// Data frame: first arrival sets the block deadline.
		if len(st.data) == 0 && len(st.parity) == 0 {
			st.deadline = time.Now().Add(d.params.BlockTimeout)
		}
		st.data[f.Seq] = f.Payload
	}
	return d.maybeDeliver(key, st)
}

// Tick flushes blocks whose deadline passed with partial data (delivers
// whatever data frames arrived, in seq order). Call from the tunnel's
// ticker.
func (d *Decoder) Tick(now time.Time) []*frame.Frame {
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.params.Enabled() {
		return nil
	}
	var out []*frame.Frame
	for key, st := range d.blocks {
		if st.flushed || now.Before(st.deadline) {
			continue
		}
		out = append(out, d.flush(key, st)...)
	}
	return out
}

// maybeDeliver completes the block when enough shards are held.
func (d *Decoder) maybeDeliver(key blockKey, st *blockState) []*frame.Frame {
	if st.k == 0 {
		return nil // parity not seen yet; nothing to reconstruct against
	}
	if len(st.data)+len(st.parity) < st.k {
		return nil
	}
	if len(st.data) == st.k {
		return d.flush(key, st) // all data present, no reconstruction
	}
	return d.reconstruct(key, st)
}

// addParity parses the self-describing sub-header and stores the shard.
func (d *Decoder) addParity(st *blockState, f *frame.Frame) error {
	if len(f.Payload) < parityHdrFixed {
		return errors.New("fec: parity payload too short")
	}
	if st.parity == nil {
		st.parity = make(map[int][]byte)
	}
	if st.data == nil {
		st.data = make(map[uint32][]byte)
	}
	k := int(binary.BigEndian.Uint16(f.Payload[0:2]))
	pidx := int(binary.BigEndian.Uint16(f.Payload[2:4]))
	maxLen := int(binary.BigEndian.Uint16(f.Payload[4:6]))
	need := parityHdrFixed + 4*k + 2*k + maxLen
	if len(f.Payload) < need {
		return errors.New("fec: parity payload truncated")
	}
	if st.k == 0 {
		st.k = k
		st.maxLen = maxLen
		st.seqs = make([]uint32, k)
		st.lens = make([]uint16, k)
		for i := 0; i < k; i++ {
			st.seqs[i] = binary.BigEndian.Uint32(f.Payload[parityHdrFixed+4*i:])
			st.lens[i] = binary.BigEndian.Uint16(f.Payload[parityHdrFixed+4*k+2*i:])
		}
		if len(st.data) == 0 && len(st.parity) == 0 {
			st.deadline = time.Now().Add(d.params.BlockTimeout)
		}
	}
	if st.k != k || st.maxLen != maxLen {
		return errors.New("fec: inconsistent parity sub-header within block")
	}
	shard := make([]byte, maxLen)
	copy(shard, f.Payload[parityHdrFixed+4*k+2*k:])
	st.parity[pidx] = shard
	return nil
}

// reconstruct fills missing data shards via RS and emits the block.
func (d *Decoder) reconstruct(key blockKey, st *blockState) []*frame.Frame {
	n := st.k + d.params.ParityShards
	shards := make([][]byte, n)
	for i, seq := range st.seqs {
		if payload, ok := st.data[seq]; ok {
			shards[i] = make([]byte, st.maxLen)
			copy(shards[i], payload)
		}
	}
	for pidx, shard := range st.parity {
		if st.k+pidx < n {
			shards[st.k+pidx] = shard
		}
	}
	if err := d.rs.Reconstruct(shards); err != nil {
		// Not enough shards after all — deliver what we have on timeout.
		return nil
	}
	for i, seq := range st.seqs {
		if _, ok := st.data[seq]; !ok {
			payload := make([]byte, st.lens[i])
			copy(payload, shards[i][:st.lens[i]])
			st.data[seq] = payload
		}
	}
	return d.flush(key, st)
}

// flush emits the block's data frames in seq order and marks it done.
func (d *Decoder) flush(key blockKey, st *blockState) []*frame.Frame {
	st.flushed = true
	sk := streamKey{sessionID: key.sessionID, path: key.path}
	if key.blockSeq > d.lastFlushed[sk] {
		d.lastFlushed[sk] = key.blockSeq
	}
	if len(st.seqs) == 0 {
		// No parity ever arrived: emit whatever data we hold, sorted.
		out := make([]*frame.Frame, 0, len(st.data))
		seqs := make([]uint32, 0, len(st.data))
		for seq := range st.data {
			seqs = append(seqs, seq)
		}
		sortUint32(seqs)
		for _, seq := range seqs {
			out = append(out, &frame.Frame{
				SessionID: key.sessionID,
				Seq:       seq,
				Payload:   st.data[seq],
			})
		}
		delete(d.blocks, key)
		return out
	}
	out := make([]*frame.Frame, 0, len(st.seqs))
	for _, seq := range st.seqs {
		payload, ok := st.data[seq]
		if !ok {
			continue
		}
		out = append(out, &frame.Frame{
			SessionID: key.sessionID,
			Seq:       seq,
			Payload:   payload,
		})
	}
	delete(d.blocks, key)
	return out
}

func sortUint32(s []uint32) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
