// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package blake2b

import (
	"testing"
)

func TestBlockSize(t *testing.T) {
	h, err := New(64, nil)
	if err != nil {
		t.Fatalf("Failed to create BLAKE2b instance: %s", err)
	}
	if bs := h.BlockSize(); bs != BlockSize {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, BlockSize)
	}
}

func TestSize(t *testing.T) {
	h, err := New(64, nil)
	if err != nil {
		t.Fatalf("Failed to create BLAKE2b instance: %s", err)
	}
	if s := h.Size(); s != 64 {
		t.Fatalf("Size() returned: %d - but expected: %d", s, 64)
	}

	h, err = New(32, nil)
	if err != nil {
		t.Fatalf("Failed to create BLAKE2b instance: %s", err)
	}
	if s := h.Size(); s != 32 {
		t.Fatalf("Size() returned: %d - but expected: %d", s, 64)
	}
}

func TestReset(t *testing.T) {
	h, err := New(32, &Config{
		Key:      make([]byte, 64),
		Salt:     make([]byte, 16),
		Personal: make([]byte, 8),
	})
	if err != nil {
		t.Fatalf("Failed to create BLAKE2b instance: %s", err)
	}

	s, ok := h.(*hashFunc)
	if !ok {
		t.Fatal("Impossible situation: New returns no blake2b struct")
	}
	orig := *s // copy

	s.Write(make([]byte, (2*BlockSize)+1))
	s.Reset()

	if s.hVal != orig.hVal {
		t.Fatalf("Reseted hVal field: %v - but expected: %v", s.hVal, orig.hVal)
	}
	if s.hValCpy != orig.hValCpy {
		t.Fatalf("Reseted hValCpy field: %v - but expected: %v", s.hValCpy, orig.hValCpy)
	}
	if s.block != orig.block {
		t.Fatalf("Reseted block field: %v - but expected: %v", s.block, orig.block)
	}
	if s.ctr != orig.ctr {
		t.Fatalf("Reseted ctr field: %v - but expected: %v", s.ctr, orig.ctr)
	}
	if s.key != orig.key {
		t.Fatalf("Reseted key field: %v - but expected: %v", s.key, orig.key)
	}
	if s.off != orig.off {
		t.Fatalf("Reseted off field %d - but expected %d", s.off, orig.off)
	}
	if s.hasKey != orig.hasKey {
		t.Fatalf("Reseted hasKey field %v - but expected %v", s.hasKey, orig.hasKey)

	}
}

func TestNew(t *testing.T) {
	_, err := New(0, nil)
	if err == nil {
		t.Fatal("New allowed 0 for hash size")
	}
}

func TestSum(t *testing.T) {
	_, err := Sum(nil, 0, nil)
	if err == nil {
		t.Fatal("Sum allowed 0 for hash size")
	}
}

func TestConfigure(t *testing.T) {
	var hval [8]uint64

	err := Configure(&hval, 0, nil)
	if err == nil {
		t.Fatal("Configure allowed 0 for hash size")
	}
	err = Configure(&hval, Size+1, nil)
	if err == nil {
		t.Fatalf("Configure allowed %d for hash size", Size+1)
	}
	err = Configure(&hval, Size, &Config{Key: make([]byte, Size+1)})
	if err == nil {
		t.Fatalf("Configure allowed key with length %d", Size+1)
	}
	err = Configure(&hval, Size, &Config{Salt: make([]byte, 17)})
	if err == nil {
		t.Fatalf("Configure allowed salt with length %d", 17)
	}
	err = Configure(&hval, Size, &Config{Personal: make([]byte, 17)})
	if err == nil {
		t.Fatalf("Configure allowed personal with length %d", 17)
	}
}

// Benchmarks

func benchmarkWrite(b *testing.B, size int) {
	h, err := New(64, nil)
	if err != nil {
		b.Fatalf("Failed to create BLAKE2s instance: %s", err)
	}
	buf := make([]byte, size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func benchmarkSum(b *testing.B, size int) {
	buf := make([]byte, size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(buf, 64, nil)
	}
}

func BenchmarkWrite_64(b *testing.B) { benchmarkWrite(b, 64) }
func BenchmarkWrite_1K(b *testing.B) { benchmarkWrite(b, 1024) }
func BenchmarkSum_64(b *testing.B)   { benchmarkSum(b, 64) }
func BenchmarkSum_1K(b *testing.B)   { benchmarkSum(b, 1024) }
