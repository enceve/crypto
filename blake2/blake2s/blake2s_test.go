// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package blake2s

import (
	"testing"
)

var sum []byte = make([]byte, 32)

func BenchmarkWrite64B(b *testing.B) {
	h, err := New(32, nil)
	if err != nil {
		b.Fatalf("Failed to create BLAKE2s instance: %s", err)
	}
	buf := make([]byte, 64)
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
	sum = h.Sum(sum[:0])
}

func BenchmarkWrite1K(b *testing.B) {
	h, err := New(32, nil)
	if err != nil {
		b.Fatalf("Failed to create BLAKE2s instance: %s", err)
	}
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
	sum = h.Sum(sum[:0])
}

func BenchmarkWrite64K(b *testing.B) {
	h, err := New(32, nil)
	if err != nil {
		b.Fatalf("Failed to create BLAKE2s instance: %s", err)
	}
	buf := make([]byte, 64*1024)
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
	sum = h.Sum(sum[:0])
}

func BenchmarkSum64B(b *testing.B) {
	buf := make([]byte, 64)
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		sum, _ = Sum(buf, 32, nil)
	}
}

func BenchmarkSum1K(b *testing.B) {
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		sum, _ = Sum(buf, 32, nil)
	}
}

func BenchmarkSum64K(b *testing.B) {
	buf := make([]byte, 64*1024)
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		sum, _ = Sum(buf, 32, nil)
	}
}
