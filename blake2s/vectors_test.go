// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package blake2s

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func decodeHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		if t == nil {
			panic(err)
		}
		t.Fatalf("Failed to decode hex: %s\nCaused by: %s", s, err)
	}
	return b
}

type testVector struct {
	params    *Params
	msg, hash string
}

var vectors []testVector = []testVector{
	// Test vectors from https://blake2.net/blake2s-test.txt
	testVector{
		// without explicit hash size (check if default is used)
		params: &Params{Key: decodeHex(nil, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
		msg:    hex.EncodeToString([]byte("")),
		hash:   "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
	},
	testVector{
		params: &Params{HashSize: 32,
			Key: decodeHex(nil, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
		msg:  "00",
		hash: "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1",
	},
	testVector{
		params: &Params{HashSize: 32,
			Key: decodeHex(nil, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
		msg:  "000102030405060708090a",
		hash: "e33c4c9bd0cc7e45c80e65c77fa5997fec7002738541509e68a9423891e822a3",
	},
	testVector{
		params: &Params{HashSize: 32,
			Key: decodeHex(nil, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
		msg:  "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		hash: "c03bc642b20959cbe133a0303e0c1abff3e31ec8e1a328ec8565c36decff5265",
	},
	testVector{
		params: &Params{HashSize: 32,
			Key: decodeHex(nil, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
		msg: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414" +
			"2434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6061626364" +
			"65666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868" +
			"788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9" +
			"aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbc" +
			"ccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedee" +
			"eff0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
		hash: "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd",
	},
}

func TestVectors(t *testing.T) {
	for i, v := range vectors {
		h, err := New(v.params)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to create new blake2s hash: %s", i, err)
		}
		msg := decodeHex(t, v.msg)
		expSum := decodeHex(t, v.hash)

		h.Write(msg)
		sum := h.Sum(nil)
		if !bytes.Equal(sum, expSum) {
			t.Fatalf("Test vector %d : Hash does not match:\nFound:    %s\nExpected: %s", i, hex.EncodeToString(sum), hex.EncodeToString(expSum))
		}

		sum, err = Sum(msg, v.params)
		if err != nil {
			t.Fatalf("Test vector %d : funcion Sum failed - Cause: %s", i, err)
		}
		if !bytes.Equal(sum, expSum) {
			t.Fatalf("Test vector %d : Hash does not match:\nFound:    %s\nExpected: %s", i, hex.EncodeToString(sum), hex.EncodeToString(expSum))
		}
	}
}
