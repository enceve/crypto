// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package serpent

import (
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

// Benchmarks

func BenchmarkEncrypt(b *testing.B) {
	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create Serpent instance - Cause: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkDecrypt(b *testing.B) {
	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create Serpent instance - Cause: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(buf, buf)
	}
}

func BenchmarkKeySchedule(b *testing.B) {
	key := make([]byte, 32)
	c := new(blockCipher)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		keySchedule(key, &(c.sk))
	}
}
