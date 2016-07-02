// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package camellia

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type testVector struct {
	key, plaintext, ciphertext string
}

func fromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// Test vectors from RFC3713 - https://www.ietf.org/rfc/rfc3713.txt
var vectors = []struct {
	key, plaintext, ciphertext string
}{
	{
		key:        "0123456789abcdeffedcba9876543210",
		plaintext:  "0123456789abcdeffedcba9876543210",
		ciphertext: "67673138549669730857065648eabe43",
	},
	{
		key:        "0123456789abcdeffedcba98765432100011223344556677",
		plaintext:  "0123456789abcdeffedcba9876543210",
		ciphertext: "b4993401b3e996f84ee5cee7d79b09b9",
	},
	{
		key:        "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
		plaintext:  "0123456789abcdeffedcba9876543210",
		ciphertext: "9acc237dff16d76c20ef7c919e3a7509",
	},
}

func TestVectors(t *testing.T) {
	for i, v := range vectors {
		key := fromHex(v.key)
		plaintext := fromHex(v.plaintext)
		ciphertext := fromHex(v.ciphertext)
		buf := make([]byte, BlockSize)

		c, err := NewCipher(key)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to create Camellia instance: %s", i, err)
		}

		c.Encrypt(buf, plaintext)
		if !bytes.Equal(ciphertext, buf) {
			t.Fatalf("Test vector %d:\nEncryption failed\nFound:    %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(ciphertext))
		}
		c.Decrypt(buf, buf)
		if !bytes.Equal(plaintext, buf) {
			t.Fatalf("Test vector %d:\nDecryption failed\nFound:    %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(plaintext))
		}
	}
}
