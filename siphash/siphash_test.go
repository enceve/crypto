// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package siphash

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

type testVector struct {
	key, msg string
	hash     uint64
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

func TestBlockSize(t *testing.T) {
	h, err := New(make([]byte, KeySize))
	if err != nil {
		t.Fatalf("Could not create siphash instance: %s", err)
	}
	if bs := h.BlockSize(); bs != BlockSize || bs != 8 {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, 8)
	}
}

func TestSize(t *testing.T) {
	h, err := New(make([]byte, KeySize))
	if err != nil {
		t.Fatalf("Could not create siphash instance: %s", err)
	}
	if bs := h.Size(); bs != Size || bs != 8 {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, 8)
	}
}

func TestReset(t *testing.T) {
	h, err := New(make([]byte, KeySize))
	if err != nil {
		t.Fatalf("Could not create siphash instance: %s", err)
	}
	s, ok := h.(*siphash)
	if !ok {
		t.Fatal("Impossible situation: New returns no siphash struct")
	}
	orig := *s // copy

	var randData [BlockSize]byte
	if _, err := rand.Read(randData[:]); err != nil {
		t.Fatalf("Failed to read random bytes form crypto/rand: %s", err)
	}

	s.Write(randData[:])
	s.Reset()

	if s.buf != orig.buf {
		t.Fatalf("Reseted buf field: %d - but expected: %d", s.buf, orig.buf)
	}
	if s.ctr != orig.ctr {
		t.Fatalf("Reseted ctr field: %v - but expected: %v", s.ctr, orig.ctr)
	}
	if s.k0 != orig.k0 {
		t.Fatalf("Reseted k0 field: %v - but expected: %v", s.k0, orig.k0)
	}
	if s.k1 != orig.k1 {
		t.Fatalf("Reseted k1 field: %d - but expected: %d", s.k1, orig.k1)
	}
	if s.off != orig.off {
		t.Fatalf("Reseted off field %v - but expected %v", s.off, orig.off)
	}
}

func TestWrite(t *testing.T) {
	key := make([]byte, KeySize)
	h, err := New(key)
	if err != nil {
		t.Fatalf("Failed to create instance of siphash - Cause: %s", err)
	}
	n, err := h.Write(nil)
	if n != 0 || err != nil {
		t.Fatalf("Failed to process nil slice: Processed bytes: %d - Returned error: %s", n, err)
	}
	n, err = h.Write(make([]byte, h.Size()))
	if n != h.Size() || err != nil {
		t.Fatalf("Failed to process 0-slice with length %d: Processed bytes: %d - Returned error: %s", h.Size(), n, err)
	}
	n, err = h.Write(make([]byte, h.BlockSize()))
	if n != h.BlockSize() || err != nil {
		t.Fatalf("Failed to process 0-slice with length %d: Processed bytes: %d - Returned error: %s", h.BlockSize(), n, err)
	}
	n, err = h.Write(make([]byte, 211)) // 211 = (2*3*5*7)+1 is prime
	if n != 211 || err != nil {
		t.Fatalf("Failed to process 0-slice with length %d: Processed bytes: %d - Returned error: %s", 211, n, err)
	}
}

func TestNew(t *testing.T) {
	_, err := New(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create instance of siphash - Cause: %s", err)
	}
	_, err = New(make([]byte, 8))
	if err == nil {
		t.Fatalf("Key verification failed - invalid key accepted")
	}
	_, err = New(make([]byte, 18))
	if err == nil {
		t.Fatalf("Key verification failed - invalid key accepted")
	}
}

// Tests the Sum(b []byte) function declared within
// the hash.Hash interface.
func TestSum(t *testing.T) {
	h, err := New(make([]byte, KeySize))
	if err != nil {
		t.Fatalf("Failed to create siphash instance: %s", err)
	}
	var one = [1]byte{1}

	h.Sum(nil)
	h.Write(make([]byte, BlockSize))
	h.Write(one[:])

	sum1 := h.Sum(nil)
	sum2, err := Sum(append(make([]byte, BlockSize), one[:]...), make([]byte, KeySize))
	if err != nil {
		t.Fatalf("Failed to calculate siphash sum: %s", err)
	}

	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

// Tests the Sum(msg, key []byte) function declared within
// this package.
func TestSumFunc(t *testing.T) {
	h, err := New(make([]byte, KeySize))
	if err != nil {
		t.Fatalf("Failed to create siphash instance: %s", err)
	}

	h.Write(nil)
	sum1 := h.Sum(nil)
	sum2, err := Sum(nil, make([]byte, KeySize))
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}

	h, err = New(make([]byte, KeySize))
	if err != nil {
		t.Fatalf("Failed to create siphash instance: %s", err)
	}

	h.Write(make([]byte, 1))
	sum1 = h.Sum(nil)
	sum2, err = Sum(make([]byte, 1), make([]byte, KeySize))
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
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
