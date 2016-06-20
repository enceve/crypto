// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package cipher

import (
	"crypto/aes"
	"testing"
)

// Benchmarks

func BenchmarkSeal_64B(b *testing.B) {
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
	b.SetBytes(64)
	for i := 0; i < b.N; i++ {
		dst = c.Seal(dst, nonce, msg, data)
	}
}

func BenchmarkSeal_1K(b *testing.B) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create AES-128 instance: %s", err)
	}
	nonce := make([]byte, aes.BlockSize)
	c, err := NewEAX(block, block.BlockSize())
	if err != nil {
		b.Fatalf("Failed to create AES-128-EAX instance: %s", err)
	}
	msg := make([]byte, 1024)
	dst := make([]byte, len(msg)+aes.BlockSize)
	data := make([]byte, 8)
	b.SetBytes(1024)
	for i := 0; i < b.N; i++ {
		dst = c.Seal(dst, nonce, msg, data)
	}
}

func BenchmarkOpen_64B(b *testing.B) {
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
	b.SetBytes(64)
	for i := 0; i < b.N; i++ {
		dst, _ = c.Open(dst, nonce, ciphertext, data)
	}
}

func BenchmarkOpen_1K(b *testing.B) {
	block, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create AES-128 instance: %s", err)
	}
	nonce := make([]byte, aes.BlockSize)
	c, err := NewEAX(block, block.BlockSize())
	if err != nil {
		b.Fatalf("Failed to create AES-128-EAX instance: %s", err)
	}
	msg := make([]byte, 1024)
	dst := make([]byte, len(msg))
	ciphertext := make([]byte, len(msg)+aes.BlockSize)
	data := make([]byte, 8)
	ciphertext = c.Seal(ciphertext, nonce, msg, data)
	b.SetBytes(1024)
	for i := 0; i < b.N; i++ {
		dst, _ = c.Open(dst, nonce, ciphertext, data)
	}
}
