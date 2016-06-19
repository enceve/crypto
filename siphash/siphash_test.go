// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package siphash

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBlockSize(t *testing.T) {
	var key [16]byte
	h := New(&key)
	if bs := h.BlockSize(); bs != BlockSize {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, BlockSize)
	}
}

func TestSize(t *testing.T) {
	var key [16]byte
	h := New(&key)
	if bs := h.Size(); bs != BlockSize {
		t.Fatalf("Size() returned: %d - but expected: %d", bs, BlockSize)
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
	h := New(&key)

	n, err := h.Write(nil)
	if n != 0 || err != nil {
		t.Fatalf("Failed to process nil slice: Processed bytes: %d - Returned error: %s", n, err)
	}
	n, err = h.Write(make([]byte, h.Size()))
	if n != h.Size() || err != nil {
		t.Fatalf("Failed to process 0-slice with length %d: Processed bytes: %d - Returned error: %s", h.Size(), n, err)
	}
	n, err = h.Write(make([]byte, h.BlockSize()))
	if n != h.BlockSize() || err != nil {
		t.Fatalf("Failed to process 0-slice with length %d: Processed bytes: %d - Returned error: %s", h.BlockSize(), n, err)
	}
	n, err = h.Write(make([]byte, 211)) // 211 = (2*3*5*7)+1 is prime
	if n != 211 || err != nil {
		t.Fatalf("Failed to process 0-slice with length %d: Processed bytes: %d - Returned error: %s", 211, n, err)
	}
}

func TestSum(t *testing.T) {
	var key [16]byte
	h := New(&key)
	var one = [1]byte{1}

	h.Sum(nil)
	h.Write(make([]byte, BlockSize))
	h.Write(one[:])

	sum1 := h.Sum(nil)
	var sum2 [BlockSize]byte
	Sum(&sum2, append(make([]byte, BlockSize), one[:]...), &key)
	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

func TestSumFunc(t *testing.T) {
	var key [16]byte
	h := New(&key)

	h.Write(nil)
	sum1 := h.Sum(nil)
	var sum2 [BlockSize]byte
	Sum(&sum2, nil, &key)
	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}

	h = New(&key)

	h.Write(make([]byte, 1))
	sum1 = h.Sum(nil)
	Sum(&sum2, make([]byte, 1), &key)
	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

// Benchmarks

func BenchmarkWrite_8B(b *testing.B) {
	var key [16]byte
	h := New(&key)
	buf := make([]byte, 8)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkWrite_64B(b *testing.B) {
	var key [16]byte
	h := New(&key)
	buf := make([]byte, 64)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkWrite_1K(b *testing.B) {
	var key [16]byte
	h := New(&key)
	buf := make([]byte, 1024)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkWrite_64K(b *testing.B) {
	var key [16]byte
	h := New(&key)
	buf := make([]byte, 64*1024)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkSum_8B(b *testing.B) {
	var key [16]byte
	var out [BlockSize]byte
	msg := make([]byte, 8)

	b.SetBytes(int64(len(msg)))
	for i := 0; i < b.N; i++ {
		Sum(&out, msg, &key)
	}
}

func BenchmarkSum_1K(b *testing.B) {
	var key [16]byte
	var out [BlockSize]byte
	msg := make([]byte, 1024)

	b.SetBytes(int64(len(msg)))
	for i := 0; i < b.N; i++ {
		Sum(&out, msg, &key)
	}
}

func BenchmarkSum_64K(b *testing.B) {
	var key [16]byte
	var out [BlockSize]byte
	msg := make([]byte, 64*1024)

	b.SetBytes(int64(len(msg)))
	for i := 0; i < b.N; i++ {
		Sum(&out, msg, &key)
	}
}

func BenchmarkVerify_8B(b *testing.B) {
	var key [16]byte
	var hash [BlockSize]byte
	msg := make([]byte, 8)
	Sum(&hash, msg, &key)

	b.SetBytes(int64(len(msg)))
	for i := 0; i < b.N; i++ {
		Verify(&hash, msg, &key)
	}
}

func BenchmarkVerify_1K(b *testing.B) {
	var key [16]byte
	var hash [BlockSize]byte
	msg := make([]byte, 1024)
	Sum(&hash, msg, &key)

	b.SetBytes(int64(len(msg)))
	for i := 0; i < b.N; i++ {
		Verify(&hash, msg, &key)
	}
}

func BenchmarkVerify_64K(b *testing.B) {
	var key [16]byte
	var hash [BlockSize]byte
	msg := make([]byte, 64*1024)
	Sum(&hash, msg, &key)

	b.SetBytes(int64(len(msg)))
	for i := 0; i < b.N; i++ {
		Verify(&hash, msg, &key)
	}
}
