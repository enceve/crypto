// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package hc128

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors from the HC128 description by Hongjun Wu.
// http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
// The byte order was changed: 0x73150082 -> 0x82001573
var vectors128 = []struct {
	key, nonce, keystream string
}{
	{
		key:       "00000000000000000000000000000000",
		nonce:     "00000000000000000000000000000000",
		keystream: "82001573a003fd3b7fd72ffb0eaf63aac62f12deb629dca72785a66268ec758b",
	},
	{
		key:       "00000000000000000000000000000000",
		nonce:     "01000000000000000000000000000000",
		keystream: "d59318c058e9dbb798ec658f046617642467fc36ec6e2cc8a7381c1b952ab4c9",
	},
	{
		key:       "55000000000000000000000000000000",
		nonce:     "00000000000000000000000000000000",
		keystream: "a45182510a93b40431f92ab032f039067aa4b4bc0b482257729ff92b66e5c0cd",
	},
}

func TestVectors(t *testing.T) {
	for i, v := range vectors128 {
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex key: %s", i, err)
		}
		nonce, err := hex.DecodeString(v.nonce)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex nonce: %s", i, err)
		}
		keystream, err := hex.DecodeString(v.keystream)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex keystream: %s", i, err)
		}
		var Key, Nonce [16]byte
		copy(Key[:], key)
		copy(Nonce[:], nonce)

		c := NewCipher(&Nonce, &Key)

		buf := make([]byte, len(keystream))

		c.XORKeyStream(buf, buf)
		if !bytes.Equal(buf, keystream) {
			t.Fatalf("Test vector %d: Unexpected keystream:\nFound:    %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(keystream))
		}
	}
}
