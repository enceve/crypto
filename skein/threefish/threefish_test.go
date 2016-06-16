// Use of this source code is governed by a license
// that can be found in the LICENSE file

package threefish

import "testing"

func BenchmarkEncrypt256_32B(b *testing.B) {
	var key [32]byte
	var tweak [TweakSize]byte

	c, _ := NewCipher(&tweak, key[:])
	buf := make([]byte, BlockSize256)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkEncrypt256_1K(b *testing.B) {
	var key [32]byte
	var tweak [TweakSize]byte

	c, _ := NewCipher(&tweak, key[:])
	buf := make([]byte, 32*BlockSize256)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		for j := 0; j < 32; j++ {
			b := buf[j*BlockSize256:]
			c.Encrypt(b, b)
		}
	}
}

func BenchmarkEncrypt512_64B(b *testing.B) {
	var key [64]byte
	var tweak [TweakSize]byte

	c, _ := NewCipher(&tweak, key[:])
	buf := make([]byte, BlockSize512)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkEncrypt512_1K(b *testing.B) {
	var key [64]byte
	var tweak [TweakSize]byte

	c, _ := NewCipher(&tweak, key[:])
	buf := make([]byte, 16*BlockSize512)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		for j := 0; j < 16; j++ {
			b := buf[j*BlockSize512:]
			c.Encrypt(b, b)
		}
	}
}

func BenchmarkEncrypt1024_128B(b *testing.B) {
	var key [128]byte
	var tweak [TweakSize]byte

	c, _ := NewCipher(&tweak, key[:])
	buf := make([]byte, BlockSize1024)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkEncrypt1024_1K(b *testing.B) {
	var key [128]byte
	var tweak [TweakSize]byte

	c, _ := NewCipher(&tweak, key[:])
	buf := make([]byte, 8*BlockSize1024)

	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		for j := 0; j < 8; j++ {
			b := buf[j*BlockSize1024:]
			c.Encrypt(b, b)
		}
	}
}
