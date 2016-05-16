// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package siphash

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// Tests Blocksize() declared in hash.Hash
func TestBlockSize(t *testing.T) {
	h, err := New(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create siphash instance: %s", err)
	}
	if bs := h.BlockSize(); bs != BlockSize {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, BlockSize)
	}
}

// Tests Size() declared in hash.Hash
func TestSize(t *testing.T) {
	h, err := New(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create siphash instance: %s", err)
	}
	if bs := h.Size(); bs != Size {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, BlockSize)
	}
}

// Tests Reset() declared in hash.Hash
func TestReset(t *testing.T) {
	h, err := New(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create siphash instance: %s", err)
	}
	s, ok := h.(*hashFunc)
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

// Tests Write(p []byte) declared in hash.Hash
func TestWrite(t *testing.T) {
	key := make([]byte, 16)
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

// Tests Sum(b []byte) declared in hash.Hash
func TestSum(t *testing.T) {
	var key [16]byte
	h, err := New(key[:])
	if err != nil {
		t.Fatalf("Failed to create siphash instance: %s", err)
	}
	var one = [1]byte{1}

	h.Sum(nil)
	h.Write(make([]byte, BlockSize))
	h.Write(one[:])

	sum1 := h.Sum(nil)
	var sum2 [Size]byte
	Sum(&sum2, append(make([]byte, BlockSize), one[:]...), &key)
	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

// Tests New(key []byte) declared here (siphash)
func TestNew(t *testing.T) {
	_, err := New(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create instance of siphash: %s", err)
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

// Tests Sum(msg, key []byte) declared here (siphash)
func TestSumFunc(t *testing.T) {
	var key [16]byte
	h, err := New(key[:])
	if err != nil {
		t.Fatalf("Failed to create siphash instance: %s", err)
	}

	h.Write(nil)
	sum1 := h.Sum(nil)
	var sum2 [Size]byte
	Sum(&sum2, nil, &key)
	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}

	h, err = New(key[:])
	if err != nil {
		t.Fatalf("Failed to create siphash instance: %s", err)
	}

	h.Write(make([]byte, 1))
	sum1 = h.Sum(nil)
	Sum(&sum2, make([]byte, 1), &key)
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}
