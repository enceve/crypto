// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package siphash

import (
	"bytes"
	"encoding/hex"
	"testing"
	"unsafe"
)

func TestBlockSize(t *testing.T) {
	var key [16]byte
	h := New(&key)
	if bs := h.BlockSize(); bs != 8 {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, 8)
	}
}

func TestSize(t *testing.T) {
	var key [16]byte
	h := New(&key)
	if bs := h.Size(); bs != 8 {
		t.Fatalf("Size() returned: %d - but expected: %d", bs, 8)
	}
}

func TestReset(t *testing.T) {
	var key [16]byte
	h := New(&key)
	s, ok := h.(*hashFunc)
	if !ok {
		t.Fatal("Impossible situation: New returns no siphash struct")
	}
	orig := *s // copy

	s.Write(make([]byte, 18))
	s.Reset()

	if s.hVal != orig.hVal {
		t.Fatalf("Reseted hVal field: %d - but expected: %d", s.block, orig.block)
	}
	if s.block != orig.block {
		t.Fatalf("Reseted block field: %d - but expected: %d", s.block, orig.block)
	}
	if s.ctr != orig.ctr {
		t.Fatalf("Reseted ctr field: %v - but expected: %v", s.ctr, orig.ctr)
	}
	if s.key != orig.key {
		t.Fatalf("Reseted key field: %v - but expected: %v", s.key, orig.key)
	}
	if s.off != orig.off {
		t.Fatalf("Reseted off field %v - but expected %v", s.off, orig.off)
	}
}

func TestWrite(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}

	h := New(&key)

	var msg1 []byte
	msg0 := make([]byte, 64)
	for i := range msg0 {
		h.Write(msg0[:i])
		msg1 = append(msg1, msg0[:i]...)
	}

	if tag0, tag1 := h.Sum64(), Sum64(msg1, &key); tag0 != tag1 {
		t.Fatalf("Sum64 differ from siphash.Sum64\n Sum64: %x \n siphash.Sum64: %x", tag0, tag1)
	}
}

func TestSum(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}
	h := New(&key)

	msg := make([]byte, 64)
	var tag [8]byte
	for i := range msg {
		h.Write(msg[:i])
		sum := h.Sum(nil)
		h.Reset()

		Sum(&tag, msg[:i], &key)

		if !bytes.Equal(sum, tag[:]) {
			t.Fatalf("Iteration %d: Sum differ from siphash.Sum\n Sum: %s \n sipash.Sum %s", i, hex.EncodeToString(sum), hex.EncodeToString(tag[:]))
		}
	}
}

func TestVerify(t *testing.T) {
	var key [16]byte
	for i := range key {
		key[i] = byte(i)
	}
	h := New(&key)

	msg := make([]byte, 64)
	var tag [8]byte
	for i := range msg {
		h.Write(msg[:i])
		h.Sum(tag[:0])
		h.Reset()

		if !Verify(&tag, msg[:i], &key) {
			t.Fatalf("Iteration %d: Verify failed: %s not accepted ", i, hex.EncodeToString(tag[:]))
		}
	}
}

// Benchmarks

func BenchmarkWrite_8(b *testing.B)           { benchmarkWrite(b, 8, false) }
func BenchmarkWriteUnaligned_8(b *testing.B)  { benchmarkWrite(b, 8, true) }
func BenchmarkWrite_1K(b *testing.B)          { benchmarkWrite(b, 1024, false) }
func BenchmarkWriteUnaligned_1K(b *testing.B) { benchmarkWrite(b, 1024, true) }
func BenchmarkSum_8(b *testing.B)             { benchmarkWrite(b, 8, false) }
func BenchmarkSumUnaligned_8(b *testing.B)    { benchmarkWrite(b, 8, true) }
func BenchmarkSum_1K(b *testing.B)            { benchmarkWrite(b, 1024, false) }
func BenchmarkSumUnaligned_1K(b *testing.B)   { benchmarkWrite(b, 1024, true) }

func unalignBytes(in []byte) []byte {
	out := make([]byte, len(in)+1)
	if uintptr(unsafe.Pointer(&out[0]))&(unsafe.Alignof(uint32(0))-1) == 0 {
		out = out[1:]
	} else {
		out = out[:len(in)]
	}
	copy(out, in)
	return out
}

func benchmarkWrite(b *testing.B, size int, unalign bool) {
	var key [16]byte
	h := New(&key)
	msg := make([]byte, size)
	if unalign {
		msg = unalignBytes(msg)
	}

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}

func benchmarkSum(b *testing.B, size int, unalign bool) {
	var out [TagSize]byte
	var key [16]byte
	msg := make([]byte, size)
	if unalign {
		msg = unalignBytes(msg)
	}

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(&out, msg, &key)
	}
}
