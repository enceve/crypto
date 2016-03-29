// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package serpent

import (
	"encoding/hex"
	"testing"
)

// Tests the S-Box 0 and its inverse.
func TestSBox0(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb0(&v0, &v1, &v2, &v3)
		sb0Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("Sbox 0 failed")
		}
	}
}

// Tests the S-Box 1 and its inverse.
func TestSBox1(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb1(&v0, &v1, &v2, &v3)
		sb1Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 1 failed")
		}
	}
}

// Tests the S-Box 2 and its inverse.
func TestSBox2(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb2(&v0, &v1, &v2, &v3)
		sb2Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 2 failed")
		}
	}
}

// Tests the S-Box 3 and its inverse.
func TestSBox3(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb3(&v0, &v1, &v2, &v3)
		sb3Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 3 failed")
		}
	}
}

// Tests the S-Box 4 and its inverse.
func TestSBox4(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb4(&v0, &v1, &v2, &v3)
		sb4Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 4 failed")
		}
	}
}

// Tests the S-Box 5 and its inverse.
func TestSBox5(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb5(&v0, &v1, &v2, &v3)
		sb5Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 5 failed")
		}
	}
}

// Tests the S-Box 6 and its inverse.
func TestSBox6(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb6(&v0, &v1, &v2, &v3)
		sb6Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 6 failed")
		}
	}
}

// Tests the S-Box 7 and its inverse.
func TestSBox7(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3

		i0, i1, i2, i3 := v0, v1, v2, v3
		sb7(&v0, &v1, &v2, &v3)
		sb7Inv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("sbox 7 failed")
		}
	}
}

// Tests the linear transformation and its inverse
func TestLinear(t *testing.T) {
	v0, v1, v2, v3 := uint32(0), uint32(0), uint32(0), uint32(0)
	for i := 0; i < 16; i++ {
		v0, v1, v2, v3 = v3+v0+uint32(i), v0+v1, v1+v2, v2+v3
		i0, i1, i2, i3 := v0, v1, v2, v3
		linear(&v0, &v1, &v2, &v3)
		linearInv(&v0, &v1, &v2, &v3)

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("linear function failed")
		}
	}
}

// A serpent test vector consisting of key,
// plaintext and expected ciphertext.
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
func TestSerpent(t *testing.T) {
	for i, v := range vectors {
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex key - Caused by: %s", i, err)
		}
		plaintext, err := hex.DecodeString(v.plaintext)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex plaintext - Caused by: %s", i, err)
		}
		ciphertext, err := hex.DecodeString(v.ciphertext)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex ciphertext - Caused by: %s", i, err)
		}
		c, err := New(key)
		if err != nil {
			t.Fatal("Test vector %d: Failed to create cipher instance - Caused by: %s", i, err)
		}

		buf := make([]byte, BlockSize)

		c.Encrypt(buf, plaintext)
		for j := range buf {
			if ciphertext[j] != buf[j] {
				t.Fatalf("Test vector %d:\nEncryption failed\nFound:    %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(ciphertext))
			}
		}
		c.Decrypt(buf, buf)
		for j := range buf {
			if plaintext[j] != buf[j] {
				t.Fatalf("Test vector %d:\nFound:    %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(plaintext))
			}
		}
	}
}
