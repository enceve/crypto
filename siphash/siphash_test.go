package siphash

import (
	"encoding/hex"
	"testing"
)

type testVector struct {
	key, src string
	value    uint64
}

var vectors []testVector = []testVector{
	// Test vector from https://131002.net/siphash/siphash.pdf
	testVector{
		key:   "000102030405060708090a0b0c0d0e0f",
		src:   "000102030405060708090a0b0c0d0e",
		value: uint64(0xa129ca6149be45e5),
	},
}

// Tests the SipHash implementation
func TestSipHash(t *testing.T) {
	for i := range vectors {
		testSingleVector(t, &vectors[i])
	}
}

func testSingleVector(t *testing.T, vec *testVector) {
	key, err := hex.DecodeString(vec.key)
	if err != nil {
		t.Fatal(err)
	}
	src, err := hex.DecodeString(vec.src)
	if err != nil {
		t.Fatal(err)
	}

	h := New(key)
	h.Write(src)

	sum := h.Sum64()
	if sum != vec.value {
		t.Fatalf("Hash values don't match - found %x expected %x", sum, vec.value)
	}
}
