// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package cmac

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

type testVector struct {
	key, in, mac string
}

// Test vectors for CMac-AES from NIST
// http://csrc.nist.gov/publications/nistpubs/800-38B/SP_800-38B.pdf
// Appendix D
var aesVectors = []testVector{
	// AES-128 vectors
	testVector{
		key: "2b7e151628aed2a6abf7158809cf4f3c",
		in:  "",
		mac: "bb1d6929e95937287fa37d129b756746",
	},
	testVector{
		key: "2b7e151628aed2a6abf7158809cf4f3c",
		in:  "6bc1bee22e409f96e93d7e117393172a",
		mac: "070a16b46b4d4144f79bdd9dd04a287c",
	},
	testVector{
		key: "2b7e151628aed2a6abf7158809cf4f3c",
		in: "6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411",
		mac: "dfa66747de9ae63030ca32611497c827",
	},
	// AES-256 vectors
	testVector{
		key: "603deb1015ca71be2b73aef0857d7781" +
			"1f352c073b6108d72d9810a30914dff4",
		in:  "",
		mac: "028962f61b7bf89efc6b551f4667d983",
	},
	testVector{
		key: "603deb1015ca71be2b73aef0857d7781" +
			"1f352c073b6108d72d9810a30914dff4",
		in:  "6bc1bee22e409f96e93d7e117393172a",
		mac: "28a7023f452e8f82bd4bf28d8c37c35c",
	},
	testVector{
		key: "603deb1015ca71be2b73aef0857d7781" +
			"1f352c073b6108d72d9810a30914dff4",
		in: "6bc1bee22e409f96e93d7e117393172a" +
			"ae2d8a571e03ac9c9eb76fac45af8e51" +
			"30c81c46a35ce411",
		mac: "aaf3d8f1de5640c232f5b169b9c911e6",
	},
}

func TestCMac(t *testing.T) {
	for i, v := range aesVectors {
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Fatalf("vector %d: %s", i, err)
		}
		in, err := hex.DecodeString(v.in)
		if err != nil {
			t.Fatalf("vector %d: %s", i, err)
		}
		mac, err := hex.DecodeString(v.mac)
		if err != nil {
			t.Fatalf("vector %d: %s", i, err)
		}

		c, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("vector %d: %s", i, err)
		}
		h, err := New(c)
		if err != nil {
			t.Fatalf("vector %d: %s", i, err)
		}
		_, err = h.Write(in)
		if err != nil {
			t.Fatalf("vector %d: %s", i, err)
		}
		sum := h.Sum(nil)
		if !bytes.Equal(sum, mac) {
			t.Fatalf("vector %d: mac are not equal", i)
		}
		if !Verify(mac, in, c) {
			t.Fatalf("vector %d: verification of mac failed", i)
		}
	}
}
