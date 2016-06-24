package hc256

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors taken from the HC256 description by Hongjun Wu
// https://eprint.iacr.org/2004/092.pdf
// The byte order was changed:
// 0x8589075b -> 0x5b078985
var vectors256 = []struct {
	key, nonce, keystream string
}{
	{
		key:       "0000000000000000000000000000000000000000000000000000000000000000",
		nonce:     "0000000000000000000000000000000000000000000000000000000000000000",
		keystream: "5b078985d8f6f30d42c5c02fa6b6795153f06534801f89f24e74248b720b4818",
	},
	{
		key:       "0000000000000000000000000000000000000000000000000000000000000000",
		nonce:     "0100000000000000000000000000000000000000000000000000000000000000",
		keystream: "afe2a2bf4f17cee9fec2058bd1b18bb15fc042ee712b3101dd501fc60b082a50",
	},
	{
		key:       "5500000000000000000000000000000000000000000000000000000000000000",
		nonce:     "0000000000000000000000000000000000000000000000000000000000000000",
		keystream: "1c404afe4fe25fed958f9ad1ae36c06f88a65a3cc0abe223aeb3902f420ed3a8",
	},
}

func TestVectors(t *testing.T) {
	for i, v := range vectors256 {
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
		var Key, Nonce [32]byte
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
