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
	var key [16]byte
	var out [Size]byte
	msg := make([]byte, 1500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(&out, msg, &key)
	}
}

func BenchmarkVerify(b *testing.B) {
	var key [16]byte
	var hash [Size]byte
	msg := make([]byte, 1500)
	Sum(&hash, msg, &key)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(&hash, msg, &key)
	}
}
