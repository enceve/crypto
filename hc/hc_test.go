package hc

import (
	"encoding/hex"
	"testing"
)

// Checks if the keystream match the test vector.
// If not, the test fails.
func checkKeyStream(t *testing.T, buf, exp []byte) {
	for i, v := range buf {
		if v != exp[i] {
			t.Fatalf("Unexpected keystream byte: found: %d expected: %d", v, exp[i])
		}
	}
}

// A test vector consisting of the key,the initialization vector (nonce),
// and the reference keystream.
type testVector struct {
	key, iv, keystream string
}

// Test vectors are from the HC128 description by Hongjun Wu
// http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf

// The byte order was changed following:
// e.g.: 0x73150082 -> 0x82001573
var vectors128 = []testVector{
	testVector{
		key:       "00000000000000000000000000000000",
		iv:        "00000000000000000000000000000000",
		keystream: "82001573a003fd3b7fd72ffb0eaf63aac62f12deb629dca72785a66268ec758b",
	},
	testVector{
		key:       "00000000000000000000000000000000",
		iv:        "01000000000000000000000000000000",
		keystream: "d59318c058e9dbb798ec658f046617642467fc36ec6e2cc8a7381c1b952ab4c9",
	},
	testVector{
		key:       "55000000000000000000000000000000",
		iv:        "00000000000000000000000000000000",
		keystream: "a45182510a93b40431f92ab032f039067aa4b4bc0b482257729ff92b66e5c0cd",
	},
}

// Test all test vectors for the HC128 cipher
func Test128(t *testing.T) {
	for _, v := range vectors128 {
		test128(t, &v)
	}
}

// Creates a HC128 cipher form the given testVector key and iv and
// encrypts a buffer of zeros. The produced keystream is compared
// to the reference keystream.
func test128(t *testing.T, vec *testVector) {
	key, _ := hex.DecodeString(vec.key)
	iv, _ := hex.DecodeString(vec.iv)
	c, _ := New128(key, iv)
	exp, _ := hex.DecodeString(vec.keystream)
	buf := make([]byte, len(exp))

	c.XORKeyStream(buf, buf)
	checkKeyStream(t, buf, exp)
}

// Test vectors are from the HC256 description by Hongjun Wu
// https://eprint.iacr.org/2004/092.pdf

// The byte order was changed following:
// e.g.: 0x8589075b -> 0x5b078985
var vectors256 = []testVector{
	testVector{
		key:       "0000000000000000000000000000000000000000000000000000000000000000",
		iv:        "0000000000000000000000000000000000000000000000000000000000000000",
		keystream: "5b078985d8f6f30d42c5c02fa6b6795153f06534801f89f24e74248b720b4818",
	},
	testVector{
		key:       "0000000000000000000000000000000000000000000000000000000000000000",
		iv:        "0100000000000000000000000000000000000000000000000000000000000000",
		keystream: "afe2a2bf4f17cee9fec2058bd1b18bb15fc042ee712b3101dd501fc60b082a50",
	},
	testVector{
		key:       "5500000000000000000000000000000000000000000000000000000000000000",
		iv:        "0000000000000000000000000000000000000000000000000000000000000000",
		keystream: "1c404afe4fe25fed958f9ad1ae36c06f88a65a3cc0abe223aeb3902f420ed3a8",
	},
}

// Test all test vectors for the HC256 cipher
func Test256(t *testing.T) {
	for _, v := range vectors256 {
		test256(t, &v)
	}
}

// Creates a HC256 cipher form the given testVector key and iv and
// encrypts a buffer of zeros. The produced keystream is compared
// to the reference keystream.
func test256(t *testing.T, vec *testVector) {
	key, _ := hex.DecodeString(vec.key)
	iv, _ := hex.DecodeString(vec.iv)
	c, _ := New256(key, iv)
	exp, _ := hex.DecodeString(vec.keystream)
	buf := make([]byte, len(exp))

	c.XORKeyStream(buf, buf)
	checkKeyStream(t, buf, exp)
}
