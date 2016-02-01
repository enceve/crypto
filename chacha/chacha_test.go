package chacha

import (
	"encoding/hex"
	"testing"
)

// A test vector consisting of a key, nonce, reference keystream,
// the number of rounds and the start counter.
type testVector struct {
	key, nonce, keystream string
	nRounds               uint
	startCtr              uint64
}

// Test vectors from:
// https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7

// 96 bit nonce is for RFC chacha, the original chacha algorithm
// will use only 64 bit and ignore the other 32 bit.
var generalVectors = []testVector{
	testVector{
		key:       "0000000000000000000000000000000000000000000000000000000000000000",
		nonce:     "000000000000000000000000",
		keystream: "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7",
		nRounds:   DefaultRounds,
		startCtr:  Zero,
	},
	testVector{
		key:       "0000000000000000000000000000000000000000000000000000000000000001",
		nonce:     "000000000000000000000000",
		keystream: "4540f05a9f1fb296d7736e7b208e3c96eb4fe1834688d2604f450952ed432d41",
		nRounds:   DefaultRounds,
		startCtr:  Zero,
	},
}

// Test vectors from:
// https://tools.ietf.org/html/draft-agl-tls-chacha20poly1305-04#section-7
var chachaVectors = []testVector{
	testVector{
		key:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		nonce: "0001020304050607",
		keystream: "f798a189f195e66982105ffb640bb7757f579da31602fc93ec01ac56" +
			"f85ac3c134a4547b733b46413042c9440049176905d3be59ea1c53f1" +
			"5916155c2be8241a38008b9a26bc35941e2444177c8ade6689de9526" +
			"4986d95889fb60e84629c9bd9a5acb1cc118be563eb9b3a4a472f82e" +
			"09a7e778492b562ef7130e88dfe031c79db9d4f7c7a899151b9a4750" +
			"32b63fc385245fe054e3dd5a97a5f576fe064025d3ce042c566ab2c5" +
			"07b138db853e3d6959660996546cc9c4a6eafdc777c040d70eaf46f7" +
			"6dad3979e5c5360c3317166a1c894c94a371876a94df7628fe4eaaf2" +
			"ccb27d5aaae0ad7ad0f9d4b6ad3b54098746d4524d38407a6deb3ab78fab78c9",
		nRounds:  DefaultRounds,
		startCtr: Zero,
	},
	testVector{
		key:   "0000000000000000000000000000000000000000000000000000000000000000",
		nonce: "0000000000000001",
		keystream: "de9cba7bf3d69ef5e786dc63973f653a0b49e015adbff7134fcb7df137821031e85a050278a7084527214f73efc7" +
			"fa5b5277062eb7a0433e445f41e3",
		nRounds:  DefaultRounds,
		startCtr: Zero,
	},
}

// Test vector from:
// https://tools.ietf.org/html/rfc7539#section-2.4.2
var rfcVectors = []testVector{
	testVector{
		key:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		nonce: "000000000000004a00000000",
		keystream: "224f51f3401bd9e12fde276fb8631ded8c131f823d2c06e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b" +
			"9334794cba40c63e34cdea212c4cf07d41b769a6749f3f630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53a" +
			"c40c5945398b6eda1a832c89c167eacd901d7e2bf363",
		nRounds:  DefaultRounds,
		startCtr: 1,
	},
}

// Test all vectors for both chacha variants;
// the original and the RFC one.
func TestChachaGeneral(t *testing.T) {
	for _, v := range generalVectors {
		testChachaVector(t, &v)
		testChachaRFCVector(t, &v)
	}
}

// Test all vectors for the original chacha.
func TestChacha(t *testing.T) {
	for _, v := range chachaVectors {
		testChachaVector(t, &v)
	}
}

// Test all vectors for the RFC chacha.
func TestChachaRFC(t *testing.T) {
	for _, v := range rfcVectors {
		testChachaRFCVector(t, &v)
	}
}

func testChachaVector(t *testing.T, vec *testVector) {
	key, _ := hex.DecodeString(vec.key)
	nonce, _ := hex.DecodeString(vec.nonce)
	keystream, _ := hex.DecodeString(vec.keystream)

	c, _ := New(key, nonce, vec.nRounds)
	c.Counter(vec.startCtr)
	buf := make([]byte, len(keystream))

	c.XORKeyStream(buf, buf)

	checkKeyStream(t, buf, keystream)
}

func testChachaRFCVector(t *testing.T, vec *testVector) {
	key, _ := hex.DecodeString(vec.key)
	nonce, _ := hex.DecodeString(vec.nonce)
	keystream, _ := hex.DecodeString(vec.keystream)

	c, _ := NewRFC(key, nonce)
	c.Counter(uint32(vec.startCtr))
	buf := make([]byte, len(keystream))

	c.XORKeyStream(buf, buf)

	checkKeyStream(t, buf, keystream)
}

func checkKeyStream(t *testing.T, buf, exp []byte) {
	for i := range buf {
		if buf[i] != exp[i] {
			f := hex.EncodeToString(buf)
			t.Log(f)
			t.Fatalf("Unexpected keystream byte at %d: found: %x expected: %x", i, buf[i], exp[i])
		}
	}
}
