package camellia

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

type testVector struct {
	key, plaintext, ciphertext string
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

// Test vectors from RFC3713 - https://www.ietf.org/rfc/rfc3713.txt
var vectors = []testVector{
	testVector{
		key:        "0123456789abcdeffedcba9876543210",
		plaintext:  "0123456789abcdeffedcba9876543210",
		ciphertext: "67673138549669730857065648eabe43",
	},
	testVector{
		key:        "0123456789abcdeffedcba98765432100011223344556677",
		plaintext:  "0123456789abcdeffedcba9876543210",
		ciphertext: "b4993401b3e996f84ee5cee7d79b09b9",
	},
	testVector{
		key:        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
		plaintext:  "0123456789abcdeffedcba9876543210",
		ciphertext: "9acc237dff16d76c20ef7c919e3a7509",
	},
}

func TestVectors(t *testing.T) {
	for i, v := range vectors {
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex key - Cause: %s", i, err)
		}
		plaintext, err := hex.DecodeString(v.plaintext)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex plaintext - Cause: %s", i, err)
		}
		ciphertext, err := hex.DecodeString(v.ciphertext)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex ciphertext - Cause: %s", i, err)
		}
		buf := make([]byte, BlockSize)

		c, err := New(key)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to create Camellia instance - Cause: %s", i, err)
		}

		c.Encrypt(buf, plaintext)
		if !bytesEqual(ciphertext, buf) {
			t.Fatalf("Test vector %d:\nEncryption failed\nFound:    %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(ciphertext))
		}
		c.Decrypt(buf, buf)
		if !bytesEqual(plaintext, buf) {
			t.Fatalf("Test vector %d:\nDecryption failed\nFound:    %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(plaintext))
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	dst, src := make([]byte, BlockSize), make([]byte, BlockSize)
	dstCp, srcCp := make([]byte, BlockSize), make([]byte, BlockSize)

	_, err := rand.Read(src)
	if err != nil {
		t.Fatalf("Failed to read from random source: %s", err)
	}
	copy(srcCp, src)
	_, err = rand.Read(dst)
	if err != nil {
		t.Fatalf("Failed to read from random source: %s", err)
	}
	copy(dstCp, dst)

	// 128 bit key
	key := make([]byte, 16)
	_, err = rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to read from random source: %s", err)
	}
	c, err := New(key)
	if err != nil {
		t.Fatalf("Failed to create Camellia instance: %s", err)
	}
	c.Encrypt(dst, src)
	c.Decrypt(src, dst)
	if !bytesEqual(src, srcCp) {
		t.Fatalf("En/Decryption of dst to src failed\nKey: %v\nSrc:  %v\nDst: %v", key, srcCp, dst)
	}

	// 192 bit key
	key = make([]byte, 24)
	_, err = rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to read from random source: %s", err)
	}
	c, err = New(key)
	if err != nil {
		t.Fatalf("Failed to create Camellia instance: %s", err)
	}
	c.Encrypt(dst, src)
	c.Decrypt(src, dst)
	if !bytesEqual(src, srcCp) {
		t.Fatalf("En/Decryption of dst to src failed\nKey: %v\nSrc:  %v\nDst: %v", key, srcCp, dst)
	}

	// 256 bit key
	key = make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to read from random source: %s", err)
	}
	c, err = New(key)
	if err != nil {
		t.Fatalf("Failed to create Camellia instance: %s", err)
	}
	c.Encrypt(dst, src)
	c.Decrypt(src, dst)
	if !bytesEqual(src, srcCp) {
		t.Fatalf("En/Decryption of dst to src failed\nKey: %v\nSrc:  %v\nDst: %v", key, srcCp, dst)
	}
}

func BenchmarkEncrypt128(b *testing.B) {
	c, err := New(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create Camellia instance - Cause: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkEncrypt256(b *testing.B) {
	c, err := New(make([]byte, 32))
	if err != nil {
		b.Fatalf("Failed to create Camellia instance - Cause: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkDecrypt128(b *testing.B) {
	c, err := New(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create Camellia instance - Cause: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(buf, buf)
	}
}

func BenchmarkDecrypt256(b *testing.B) {
	c, err := New(make([]byte, 32))
	if err != nil {
		b.Fatalf("Failed to create Camellia instance - Cause: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(buf, buf)
	}
}

func BenchmarkKeySchedule128(b *testing.B) {
	c := new(camellia128)
	key := make([]byte, 16)
	for i := 0; i < b.N; i++ {
		c.keySchedule(key)
	}
}

func BenchmarkKeySchedule256(b *testing.B) {
	c := new(camellia)
	key := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		c.keySchedule(key)
	}
}
