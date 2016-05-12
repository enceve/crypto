// Use of this source code is governed by a license
// that can be found in the LICENSE file

package skein

import "testing"

// Benchmarks

func BenchmarkWrite256(b *testing.B) {
	h, err := New(&Params{BlockSize: Size256})
	if err != nil {
		b.Fatalf("Failed to create Skein-256 instance: %s", err)
	}
	buf := make([]byte, Size256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkWrite512(b *testing.B) {
	h := New512(64)
	buf := make([]byte, Size512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkWrite1024(b *testing.B) {
	h, err := New(&Params{BlockSize: Size1024})
	if err != nil {
		b.Fatalf("Failed to create Skein-1024 instance: %s", err)
	}
	buf := make([]byte, Size1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkNew(b *testing.B) {
	p := &Params{BlockSize: Size512}
	for i := 0; i < b.N; i++ {
		New(p)
	}
}

func BenchmarkNew512(b *testing.B) {
	for i := 0; i < b.N; i++ {
		New512(64)
	}
}
