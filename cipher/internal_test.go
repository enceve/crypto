// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package cipher

import (
	"crypto/aes"
	"testing"
)

// Benchmarks

func BenchmarkSeal(b *testing.B) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create AES-128 instance: %s", err)
	}
	nonce := make([]byte, aes.BlockSize)
	c, err := NewEAX(block, block.BlockSize())
	if err != nil {
		b.Fatalf("Failed to create AES-128-EAX instance: %s", err)
	}
	msg := make([]byte, 64)
	dst := make([]byte, len(msg)+aes.BlockSize)
	data := make([]byte, 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = c.Seal(dst, nonce, msg, data)
	}
}

func BenchmarkOpen(b *testing.B) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create AES-128 instance: %s", err)
	}
	nonce := make([]byte, aes.BlockSize)
	c, err := NewEAX(block, block.BlockSize())
	if err != nil {
		b.Fatalf("Failed to create AES-128-EAX instance: %s", err)
	}
	msg := make([]byte, 64)
	dst := make([]byte, len(msg))
	ciphertext := make([]byte, len(msg)+aes.BlockSize)
	data := make([]byte, 8)
	ciphertext = c.Seal(ciphertext, nonce, msg, data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, err = c.Open(dst, nonce, ciphertext, data)
	}
}
