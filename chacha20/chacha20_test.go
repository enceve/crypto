// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package chacha20

import (
	"testing"
)

func BenchmarkCipher64B(b *testing.B) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	c := NewCipher(&nonce, &key)
	buf := make([]byte, 64)
	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

func BenchmarkCipher256B(b *testing.B) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	c := NewCipher(&nonce, &key)
	buf := make([]byte, 256)
	b.SetBytes(256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

func BenchmarkCipher512B(b *testing.B) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	c := NewCipher(&nonce, &key)
	buf := make([]byte, 512)
	b.SetBytes(512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

func BenchmarkCipher1K(b *testing.B) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	c := NewCipher(&nonce, &key)
	buf := make([]byte, 1024)
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

func BenchmarkCipher16K(b *testing.B) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	c := NewCipher(&nonce, &key)
	buf := make([]byte, 16*1024)
	b.SetBytes(16 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

func BenchmarkCipher64K(b *testing.B) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	c := NewCipher(&nonce, &key)
	buf := make([]byte, 64*1024)
	b.SetBytes(64 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.XORKeyStream(buf, buf)
	}
}

func BenchmarkXORKeyStream64B(b *testing.B) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	buf := make([]byte, 64)
	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		XORKeyStream(buf, buf, &nonce, &key, 0)
	}
}

func BenchmarkXORKeyStream256B(b *testing.B) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	buf := make([]byte, 256)
	b.SetBytes(256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		XORKeyStream(buf, buf, &nonce, &key, 0)
	}
}

func BenchmarkXORKeyStream512B(b *testing.B) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	buf := make([]byte, 512)
	b.SetBytes(512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		XORKeyStream(buf, buf, &nonce, &key, 0)
	}
}

func BenchmarkXORKeyStream1K(b *testing.B) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	buf := make([]byte, 1024)
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		XORKeyStream(buf, buf, &nonce, &key, 0)
	}
}

func BenchmarkXORKeyStream16K(b *testing.B) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	buf := make([]byte, 16*1024)
	b.SetBytes(16 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		XORKeyStream(buf, buf, &nonce, &key, 0)
	}
}

func BenchmarkXORKeyStream64K(b *testing.B) {
	var (
		key   [32]byte
		nonce [NonceSize]byte
	)
	buf := make([]byte, 64*1024)
	b.SetBytes(64 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		XORKeyStream(buf, buf, &nonce, &key, 0)
	}
}
