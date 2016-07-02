// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package camellia

import (
	"bytes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

var recoverFail = func(t *testing.T) {
	if err := recover(); err == nil {
		t.Fatal("Recover expected error, but no one occured")
	}
}

var badKeys = [][]byte{
	make([]byte, 15),
	make([]byte, 17),
	make([]byte, 23),
	make([]byte, 25),
	make([]byte, 31),
	make([]byte, 33),
}

func TestBlockSize(t *testing.T) {
	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create camellia cipher: %s", err)
	}
	if bs := c.BlockSize(); bs != BlockSize {
		t.Fatalf("BlockSize() returned unexpected value: %d", bs)
	}

	c, err = NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create camellia cipher: %s", err)
	}
	if bs := c.BlockSize(); bs != BlockSize {
		t.Fatalf("BlockSize() returned unexpected value: %d", bs)
	}
}

func TestEncrypt(t *testing.T) {
	encFail := func(t *testing.T, c cipher.Block, srcLen, dstLen int) {
		defer recoverFail(t)
		src := make([]byte, srcLen)
		dst := make([]byte, dstLen)
		c.Encrypt(dst, src)
	}

	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create camellia cipher: %s", err)
	}
	encFail(t, c, BlockSize-1, BlockSize)
	encFail(t, c, BlockSize, BlockSize-1)

	c, err = NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create camellia cipher: %s", err)
	}
	encFail(t, c, BlockSize-1, BlockSize)
	encFail(t, c, BlockSize, BlockSize-1)
}

func TestDecrypt(t *testing.T) {
	decFail := func(t *testing.T, c cipher.Block, srcLen, dstLen int) {
		defer recoverFail(t)
		src := make([]byte, srcLen)
		dst := make([]byte, dstLen)
		c.Decrypt(dst, src)
	}

	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create camellia cipher: %s", err)
	}
	decFail(t, c, BlockSize-1, BlockSize)
	decFail(t, c, BlockSize, BlockSize-1)

	c, err = NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create camellia cipher: %s", err)
	}
	decFail(t, c, BlockSize-1, BlockSize)
	decFail(t, c, BlockSize, BlockSize-1)
}

func TestEncryptDecrypt(t *testing.T) {
	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create camellia cipher: %s", err)
	}

	src := make([]byte, 32)
	dst := make([]byte, 32)

	c.Encrypt(dst, src)
	c.Encrypt(dst[16:], src[:16])
	c.Decrypt(dst, dst)
	c.Decrypt(dst[16:], dst[16:])

	if !bytes.Equal(src, dst) {
		t.Fatalf("En / decryption sequence failed\nFound: %s\nExpected: %s", hex.EncodeToString(dst), hex.EncodeToString(src))
	}
}

func TestNewCipher(t *testing.T) {
	var (
		key128 [16]byte
		key192 [24]byte
		key256 [32]byte
	)
	_, err := NewCipher(key128[:])
	if err != nil {
		t.Fatalf("NewCipher rejected valid key with length: %d", len(key128))
	}
	_, err = NewCipher(key192[:])
	if err != nil {
		t.Fatalf("NewCipher rejected valid key with length: %d", len(key192))
	}
	_, err = NewCipher(key256[:])
	if err != nil {
		t.Fatalf("NewCipher rejected valid key with length: %d", len(key256))
	}

	for i, v := range badKeys {
		_, err := NewCipher(v)
		if err == nil {
			t.Fatalf("NewCipher accpeted bad key %d with length: %d", i, len(v))
		}
	}
}

// Benchmarks

func BenchmarkEncrypt_16(b *testing.B) { benchmarkEncrypt(b, 16) }
func BenchmarkDecrypt_16(b *testing.B) { benchmarkDecrypt(b, 16) }
func BenchmarkEncrypt_1K(b *testing.B) { benchmarkEncrypt(b, 1024) }
func BenchmarkDecrypt_1K(b *testing.B) { benchmarkDecrypt(b, 1024) }

func benchmarkEncrypt(b *testing.B, size int) {
	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create camellia instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.SetBytes(int64(size - (size % c.BlockSize())))

	n := size / c.BlockSize()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < n; j++ {
			c.Encrypt(buf, buf)
		}
	}
}

func benchmarkDecrypt(b *testing.B, size int) {
	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create camelli instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.SetBytes(int64(size - (size % c.BlockSize())))

	n := size / c.BlockSize()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for j := 0; j < n; j++ {
			c.Decrypt(buf, buf)
		}
	}
}
