package camellia

import (
	"encoding/hex"
	"testing"
)

type testVector struct {
	key, plain, cipher string
}

// Test vectors from RFC3713 - https://www.ietf.org/rfc/rfc3713.txt
var vectors = []testVector{
	testVector{
		key:    "0123456789abcdeffedcba9876543210",
		plain:  "0123456789abcdeffedcba9876543210",
		cipher: "67673138549669730857065648eabe43",
	},
	testVector{
		key:    "0123456789abcdeffedcba98765432100011223344556677",
		plain:  "0123456789abcdeffedcba9876543210",
		cipher: "b4993401b3e996f84ee5cee7d79b09b9",
	},
	testVector{
		key:    "0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff",
		plain:  "0123456789abcdeffedcba9876543210",
		cipher: "9acc237dff16d76c20ef7c919e3a7509",
	},
}

func TestCamellia(t *testing.T) {
	for i := range vectors {
		key, err := hex.DecodeString(vectors[i].key)
		if err != nil {
			t.Fatal(err)
		}
		plain, err := hex.DecodeString(vectors[i].plain)
		if err != nil {
			t.Fatal(err)
		}
		cipher, err := hex.DecodeString(vectors[i].cipher)
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, BlockSize)
		copy(buf, plain)

		c, err := New(key)
		if err != nil {
			t.Fatal(err)
		}

		c.Encrypt(buf, buf)
		for i := range buf {
			if cipher[i] != buf[i] {
				t.Fatalf("Encryption failed\nFound:    %s\nExpected: %s", hex.EncodeToString(buf), hex.EncodeToString(cipher))
			}
		}
		c.Decrypt(buf, buf)
		for i := range buf {
			if plain[i] != buf[i] {
				t.Fatalf("Decryption failed\nFound:    %s\nExpected: %s", hex.EncodeToString(buf), hex.EncodeToString(plain))
			}
		}
	}
}
