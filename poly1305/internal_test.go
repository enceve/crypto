// Use of this source code is governed by a license
// that can be found in the LICENSE file

package poly1305

import "testing"

// Benchmarks

func BenchmarkWrite(b *testing.B) {
	h, err := New(make([]byte, 32))
	if err != nil {
		b.Fatalf("Failed to create poly1305 instance: %s", err)
	}
	msg := make([]byte, 1500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}

func BenchmarkSum(b *testing.B) {
	var key [32]byte
	var tag [16]byte

	msg := make([]byte, 1500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(&tag, msg, &key)
	}
}
