// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package serpent

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

func TestEncrypt(t *testing.T) {
	encFail := func(t *testing.T, c cipher.Block, srcLen, dstLen int) {
		defer recoverFail(t)
		src := make([]byte, srcLen)
		dst := make([]byte, dstLen)
		c.Encrypt(dst, src)
	}

	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create serpent cipher: %s", err)
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
		t.Fatalf("Failed to create serpent cipher: %s", err)
	}
	decFail(t, c, BlockSize-1, BlockSize)
	decFail(t, c, BlockSize, BlockSize-1)
}

func TestEncryptDecrypt(t *testing.T) {
	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create serpent cipher: %s", err)
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

func TestBlockSize(t *testing.T) {
	s := new(subkeys)
	if bs := s.BlockSize(); bs != BlockSize {
		t.Fatalf("BlockSize() returned unexpected value: %d", bs)
	}
}

// Tests the S-Box 0 and its inverse.
func TestSBox0(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb0(&v0, &v1, &v2, &v3)
		sb0Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("Sbox 0 failed")
		}
	}
}

// Tests the S-Box 1 and its inverse.
func TestSBox1(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb1(&v0, &v1, &v2, &v3)
		sb1Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 1 failed")
		}
	}
}

// Tests the S-Box 2 and its inverse.
func TestSBox2(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb2(&v0, &v1, &v2, &v3)
		sb2Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 2 failed")
		}
	}
}

// Tests the S-Box 3 and its inverse.
func TestSBox3(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb3(&v0, &v1, &v2, &v3)
		sb3Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 3 failed")
		}
	}
}

// Tests the S-Box 4 and its inverse.
func TestSBox4(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb4(&v0, &v1, &v2, &v3)
		sb4Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 4 failed")
		}
	}
}

// Tests the S-Box 5 and its inverse.
func TestSBox5(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb5(&v0, &v1, &v2, &v3)
		sb5Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 5 failed")
		}
	}
}

// Tests the S-Box 6 and its inverse.
func TestSBox6(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb6(&v0, &v1, &v2, &v3)
		sb6Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 6 failed")
		}
	}
}

// Tests the S-Box 7 and its inverse.
func TestSBox7(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb7(&v0, &v1, &v2, &v3)
		sb7Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 7 failed")
		}
	}
}

// Tests the linear transformation and its inverse
func TestLinear(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3
		i0, i1, i2, i3 := v0, v1, v2, v3
		linear(&v0, &v1, &v2, &v3)
		linearInv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("linear function failed")
		}
	}
}

// Benchmarks

func BenchmarkEncrypt_16B(b *testing.B) {
	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create Serpent instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkEncrypt_1K(b *testing.B) {
	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create Serpent instance: %s", err)
	}
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))
	n := len(buf) / BlockSize
	for i := 0; i < b.N; i++ {
		for j := 0; j < n; j++ {
			b := buf[j*BlockSize:]
			c.Decrypt(b, b)
		}
	}
}

func BenchmarkDecrypt_16B(b *testing.B) {
	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create Serpent instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.SetBytes(int64(len(buf)))
	for i := 0; i < b.N; i++ {
		c.Decrypt(buf, buf)
	}
}

func BenchmarkDecrypt_1024B(b *testing.B) {
	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create Serpent instance: %s", err)
	}
	buf := make([]byte, 1024)
	b.SetBytes(int64(len(buf)))
	n := len(buf) / BlockSize
	for i := 0; i < b.N; i++ {
		for j := 0; j < n; j++ {
			b := buf[j*BlockSize:]
			c.Decrypt(b, b)
		}
	}
}
