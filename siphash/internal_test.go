// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package siphash

import "testing"

// Benchmarks

func BenchmarkWrite(b *testing.B) {
	h, err := New(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create siphash instance: %s", err)
	}
	buf := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkSum(b *testing.B) {
	key := make([]byte, 16)
	msg := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(msg, key)
	}
}

func BenchmarkVerify(b *testing.B) {
	key := make([]byte, 16)
	msg := make([]byte, BlockSize)
	hash, err := Sum(msg, key)
	if err != nil {
		b.Fatalf("Failed to calculate checksum - Cause: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(hash, msg, key)
	}
}
