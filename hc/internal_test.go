// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package hc

import "testing"

// Benchmarks

func BenchmarkHC128Encrypt(b *testing.B) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	c, err := NewCipher128(key, nonce)
	if err != nil {
		b.Fatalf("Failed to create HC-128 instance: %s", err)
	}
	buf := make([]byte, 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

func BenchmarkHC256Encrypt(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 32)
	c, err := NewCipher256(key, nonce)
	if err != nil {
		b.Fatalf("Failed to create HC-256 instance: %s", err)
	}
	buf := make([]byte, 16)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

func BenchmarkHC128Setup(b *testing.B) {
	key := make([]byte, 16)
	nonce := make([]byte, 16)
	c := new(streamCipher128)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.initialize(key, nonce)
	}
}

func BenchmarkHC256Setup(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 32)
	c := new(streamCipher256)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.initialize(key, nonce)
	}
}
