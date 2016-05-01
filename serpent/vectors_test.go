// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package serpent

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type testVector struct {
	key, plaintext, ciphertext string
}

// Test vectors for serpent
var vectors = []testVector{
	// test vectors for 128 bit key from
	// http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors
	testVector{ // Set 1, vector#  0
		key:        "80000000000000000000000000000000",
		plaintext:  "00000000000000000000000000000000",
		ciphertext: "264E5481EFF42A4606ABDA06C0BFDA3D",
	},
	testVector{ // Set 1, vector#  1
		key:        "40000000000000000000000000000000",
		plaintext:  "00000000000000000000000000000000",
		ciphertext: "4A231B3BC727993407AC6EC8350E8524",
	},
	// test vectors for 192 bit key from
	// http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-192-128.verified.test-vectors
	testVector{ // Set 1, vector#  0
		key:        "800000000000000000000000000000000000000000000000",
		plaintext:  "00000000000000000000000000000000",
		ciphertext: "9E274EAD9B737BB21EFCFCA548602689",
	},
	testVector{ // Set 1, vector#  3
		key:        "100000000000000000000000000000000000000000000000",
		plaintext:  "00000000000000000000000000000000",
		ciphertext: "BEC1E37824CF721E5D87F6CB4EBFB9BE",
	},
	// test vectors for 256 bit key from
	// http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors
	testVector{ // Set 3, vector#  1
		key:        "0101010101010101010101010101010101010101010101010101010101010101",
		plaintext:  "01010101010101010101010101010101",
		ciphertext: "EC9723B15B2A6489F84C4524FFFC2748",
	},
	testVector{ // Set 3, vector#  2
		key:        "0202020202020202020202020202020202020202020202020202020202020202",
		plaintext:  "02020202020202020202020202020202",
		ciphertext: "1187F485538514476184E567DA0421C7",
	},
}

// Tests all serpent test vectors.
func TestVectors(t *testing.T) {
	for i, v := range vectors {
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex key: %s", i, err)
		}
		plaintext, err := hex.DecodeString(v.plaintext)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex plaintext: %s", i, err)
		}
		ciphertext, err := hex.DecodeString(v.ciphertext)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex ciphertext: %s", i, err)
		}
		c, err := New(key)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to create cipher instance: %s", i, err)
		}

		buf := make([]byte, BlockSize)

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
