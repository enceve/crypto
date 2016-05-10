// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package cipher

import (
	"bytes"
	"crypto/aes"
	"encoding/hex"
	"testing"
)

type testVector struct {
	msg, key, nonce, data string
	ciphertext            string
	macSize               int
}

// EAX-AES test vectors from
// http://web.cs.ucdavis.edu/~rogaway/papers/eax.pdf
var vectors = []testVector{
	testVector{
		msg:        "",
		key:        "233952DEE4D5ED5F9B9C6D6FF80FF478",
		nonce:      "62EC67F9C3A4A407FCB2A8C49031A8B3",
		data:       "6BFB914FD07EAE6B",
		ciphertext: "E037830E8389F27B025A2D6527E79D01",
		macSize:    16,
	},
	testVector{
		msg:        "F7FB",
		key:        "91945D3F4DCBEE0BF45EF52255F095A4",
		nonce:      "BECAF043B0A23D843194BA972C66DEBD",
		data:       "FA3BFD4806EB53FA",
		ciphertext: "19DD5C4C9331049D0BDAB0277408F67967E5",
		macSize:    16,
	},
	testVector{
		msg:        "1A47CB4933",
		key:        "01F74AD64077F2E704C0F60ADA3DD523",
		nonce:      "70C3DB4F0D26368400A10ED05D2BFF5E",
		data:       "234A3463C1264AC6",
		ciphertext: "D851D5BAE03A59F238A23E39199DC9266626C40F80",
		macSize:    16,
	},
	testVector{
		msg:        "1A47CB4933",
		key:        "01F74AD64077F2E704C0F60ADA3DD523",
		nonce:      "70C3DB4F0D26368400A10ED05D2BFF5E",
		data:       "234A3463C1264AC6",
		ciphertext: "D851D5BAE03A59F238A23E39199DC9266626C4",
		macSize:    14,
	},
	testVector{
		msg:   "8B0A79306C9CE7ED99DAE4F87F8DD61636",
		key:   "7C77D6E813BED5AC98BAA417477A2E7D",
		nonce: "1A8C98DCD73D38393B2BF1569DEEFC19",
		data:  "65D2017990D62528",
		ciphertext: "02083E3979DA014812F59F11D52630DA30137327D10" +
			"649B0AA6E1C181DB617D7F2",
		macSize: 16,
	},
	testVector{
		msg:   "8B0A79306C9CE7ED99DAE4F87F8DD61636",
		key:   "7C77D6E813BED5AC98BAA417477A2E7D",
		nonce: "1A8C98DCD73D38393B2BF1569DEEFC19",
		data:  "65D2017990D62528",
		ciphertext: "02083E3979DA014812F59F11D52630DA30137327D10" +
			"649B0AA6E1C181D",
		macSize: 12,
	},
}

func TestVectors(t *testing.T) {
	for i, v := range vectors {
		msg, err := hex.DecodeString(v.msg)
		if err != nil {
			t.Fatalf("TestVector %d: Failed to decode hex msg: %s", i, err)
		}
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Fatalf("TestVector %d: Failed to decode hex key: %s", i, err)
		}
		nonce, err := hex.DecodeString(v.nonce)
		if err != nil {
			t.Fatalf("TestVector %d: Failed to decode hex nonce: %s", i, err)
		}
		data, err := hex.DecodeString(v.data)
		if err != nil {
			t.Fatalf("TestVector %d: Failed to decode hex data: %s", i, err)
		}
		ciphertext, err := hex.DecodeString(v.ciphertext)
		if err != nil {
			t.Fatalf("TestVector %d: Failed to decode hex ciphertext: %s", i, err)
		}
		cAES, err := aes.NewCipher(key)
		if err != nil {
			t.Fatalf("TestVector %d: Failed to create AES instance: %s", i, err)
		}
		eax, err := NewEAX(cAES, v.macSize)
		if err != nil {
			t.Fatalf("TestVector %d: Failed to create EAX instance: %s", i, err)
		}

		buf := make([]byte, len(ciphertext))
		buf = eax.Seal(buf, nonce, msg, data)

		if !bytes.Equal(buf, ciphertext) {
			t.Fatalf("TestVector %d Seal failed:\nFound   : %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(ciphertext))
		}

		buf, err = eax.Open(buf, nonce, buf, data)

		if err != nil {
			t.Fatalf("TestVector %d: Open failed: %s", i, err)
		}
		if !bytes.Equal(buf, msg) {
			t.Fatalf("TestVector %d Open failed:\nFound   : %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(msg))
		}
	}
}
