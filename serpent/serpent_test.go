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

		i0, i1, i2, i3 := sb0Inv(sb0(v0, v1, v2, v3))

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

		i0, i1, i2, i3 := sb1Inv(sb1(v0, v1, v2, v3))

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

		i0, i1, i2, i3 := sb2Inv(sb2(v0, v1, v2, v3))

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

		i0, i1, i2, i3 := sb3Inv(sb3(v0, v1, v2, v3))

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

		i0, i1, i2, i3 := sb4Inv(sb4(v0, v1, v2, v3))

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

		i0, i1, i2, i3 := sb5Inv(sb5(v0, v1, v2, v3))

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

		i0, i1, i2, i3 := sb6Inv(sb6(v0, v1, v2, v3))

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

		i0, i1, i2, i3 := sb7Inv(sb7(v0, v1, v2, v3))

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

		i0, i1, i2, i3 := linearInv(linear(v0, v1, v2, v3))

		if i0 != v0 || i1 != v1 || i2 != v2 || i3 != v3 {
			t.Fatal("linear function failed")
		}
	}
}

// A serpent test vector consisting of key,
// plaintext and expected ciphertext.
type testVector struct {
	key, plain, cipher string
}

// Test vectors for serpent
var vectors = []testVector{
	// test vectors for 128 bit key from
	// http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-128-128.verified.test-vectors
	testVector{ // Set 1, vector#  0
		key:    "80000000000000000000000000000000",
		plain:  "00000000000000000000000000000000",
		cipher: "264E5481EFF42A4606ABDA06C0BFDA3D",
	},
	testVector{ // Set 1, vector#  1
		key:    "40000000000000000000000000000000",
		plain:  "00000000000000000000000000000000",
		cipher: "4A231B3BC727993407AC6EC8350E8524",
	},
	// test vectors for 192 bit key from
	// http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-192-128.verified.test-vectors
	testVector{ // Set 1, vector#  0
		key:    "800000000000000000000000000000000000000000000000",
		plain:  "00000000000000000000000000000000",
		cipher: "9E274EAD9B737BB21EFCFCA548602689",
	},
	testVector{ // Set 1, vector#  3
		key:    "100000000000000000000000000000000000000000000000",
		plain:  "00000000000000000000000000000000",
		cipher: "BEC1E37824CF721E5D87F6CB4EBFB9BE",
	},
	// test vectors for 256 bit key from
	// http://www.cs.technion.ac.il/~biham/Reports/Serpent/Serpent-256-128.verified.test-vectors
	testVector{ // Set 3, vector#  1
		key:    "0101010101010101010101010101010101010101010101010101010101010101",
		plain:  "01010101010101010101010101010101",
		cipher: "EC9723B15B2A6489F84C4524FFFC2748",
	},
	testVector{ // Set 3, vector#  2
		key:    "0202020202020202020202020202020202020202020202020202020202020202",
		plain:  "02020202020202020202020202020202",
		cipher: "1187F485538514476184E567DA0421C7",
	},
}

// Tests all serpent test vectors.
func TestSerpent(t *testing.T) {
	for _, vec := range vectors {
		key, _ := hex.DecodeString(vec.key)
		s, _ := New(key)

		src, _ := hex.DecodeString(vec.plain)
		enc := make([]byte, BlockSize)
		dec := make([]byte, BlockSize)
		exp, _ := hex.DecodeString(vec.cipher)
		s.Encrypt(enc, src)
		s.Decrypt(dec, enc)

		for i := range enc {
			if enc[i] != exp[i] {
				t.Fatalf("Unexpected byte: found: %x but expected %x", enc[i], exp[i])
			}
			if dec[i] != src[i] {
				t.Log(dec)
				t.Fatalf("Decryption failed: found: %x but expected %x", dec[i], src[i])
			}
		}
	}
}
