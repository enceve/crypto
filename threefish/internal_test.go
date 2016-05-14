// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package threefish

import (
	"testing"
)

// Benchmarks

func BenchmarkEncrypt256(b *testing.B) {
	c, err := NewCipher(make([]byte, 32), make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create threefish-256 instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkEncrypt512(b *testing.B) {
	c, err := NewCipher(make([]byte, 64), make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create threefish-256 instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkEncrypt1024(b *testing.B) {
	c, err := NewCipher(make([]byte, 128), make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create threefish-256 instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkDecrypt256(b *testing.B) {
	c, err := NewCipher(make([]byte, 32), make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create threefish-256 instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(buf, buf)
	}
}

func BenchmarkDecrypt512(b *testing.B) {
	c, err := NewCipher(make([]byte, 64), make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create threefish-256 instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(buf, buf)
	}
}

func BenchmarkDecrypt1024(b *testing.B) {
	c, err := NewCipher(make([]byte, 128), make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create threefish-256 instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(buf, buf)
	}
}
