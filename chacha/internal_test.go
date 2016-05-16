// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package chacha

import "testing"

// Benchmarks

func BenchmarkChacha(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	c, err := NewCipher(key, nonce)
	if err != nil {
		b.Fatalf("Failed to create ChaCha instance: %s", err)
	}
	buf := make([]byte, 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

func BenchmarkXORKeyStream(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	buf := make([]byte, 64)
	for i := 0; i < b.N; i++ {
		XORKeyStream(buf, buf, &key, &nonce, 0)
	}
}

func BenchmarkXORKeyStream12(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	buf := make([]byte, 64)
	for i := 0; i < b.N; i++ {
		XORKeyStream12(buf, buf, &key, &nonce, 0)
	}
}

func BenchmarkSeal(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	c, err := NewAEAD(key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 64)
	dst := make([]byte, len(msg)+16)
	data := make([]byte, 8)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = c.Seal(dst, nonce, msg, data)
	}
}

func BenchmarkOpen(b *testing.B) {
	key := make([]byte, 32)
	nonce := make([]byte, 12)
	c, err := NewAEAD(key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 64)
	dst := make([]byte, len(msg))
	ciphertext := make([]byte, len(msg)+16)
	data := make([]byte, 8)
	ciphertext = c.Seal(ciphertext, nonce, msg, data)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = c.Open(dst, nonce, ciphertext, data)
	}
}
