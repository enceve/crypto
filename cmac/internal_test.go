// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package cmac

import (
	"crypto/aes"
	"testing"
)

// Benchmarks

func BenchmarkWrite(b *testing.B) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create AES instance - Cause: %s", err)
	}
	h, err := New(c)
	if err != nil {
		b.Fatalf("Failed to create CMac instance - Cause: %s", err)
	}
	buf := make([]byte, aes.BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkSum(b *testing.B) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create AES instance - Cause: %s", err)
	}
	msg := make([]byte, aes.BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(msg, c)
	}
}

func BenchmarkVerify(b *testing.B) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create AES instance - Cause: %s", err)
	}
	msg := make([]byte, aes.BlockSize)
	hash, err := Sum(msg, c)
	if err != nil {
		b.Fatalf("Failed to calculate checksum - Cause: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(hash, msg, c)
	}
}
