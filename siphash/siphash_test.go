// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package siphash

import (
	"encoding/hex"
	"testing"
)

type testVector struct {
	key, msg string
	hash     uint64
}

var vectors []testVector = []testVector{
	// Test vector from https://131002.net/siphash/siphash.pdf
	testVector{
		key:  "000102030405060708090a0b0c0d0e0f",
		msg:  "000102030405060708090a0b0c0d0e",
		hash: uint64(0xa129ca6149be45e5),
	},
}

// Tests the SipHash implementation
func TestVectors(t *testing.T) {
	for i, v := range vectors {
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex key - Cause: %s", i, err)
		}
		msg, err := hex.DecodeString(v.msg)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex msg - Cause: %s", i, err)
		}
		h, err := New(key)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to create Siphash instance - Cause: %s", i, err)
		}

		_, err = h.Write(msg)
		if err != nil {
			t.Fatalf("Test vector %d: Spihash write failed - Cause: %s", i, err)
		}

		sum := h.Sum64()
		if sum != v.hash {
			t.Fatalf("Test vector %d: Hash values don't match - found %x expected %x", i, sum, v.hash)
		}
		sum, err = Sum64(msg, key)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to calculate MAC - Cause: %s", i, err)
		}
		if sum != v.hash {
			t.Fatalf("Hash values don't match - found %x expected %x", sum, v.hash)
		}
	}
}

func BenchmarkWrite(b *testing.B) {
	h, err := New(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create siphash instance - Cause: %s", err)
	}
	buf := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkSum(b *testing.B) {
	key := make([]byte, 16)
	msg := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(msg, key)
	}
}

func BenchmarkVerify(b *testing.B) {
	key := make([]byte, 16)
	msg := make([]byte, BlockSize)
	hash, err := Sum(msg, key)
	if err != nil {
		b.Fatalf("Failed to calculate checksum - Cause: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Verify(hash, msg, key)
	}
}
