// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package pad

import (
	"bytes"
	"crypto/rand"
	"testing"
)

var blocksizes = [5]int{8, 16, 32, 64, 128}

var msglengths = [8]int{0, 1, 8, 16, 32, 64, 128, 249}

func generateSequence(out []byte, seed uint32) {
	a := 0xDEAD4BAD * seed // prime
	b := uint32(1)

	for i := range out { // fill the buf
		t := a + b
		a = b
		b = t
		out[i] = byte(t >> 24)
	}
}

func TestPKCS7(t *testing.T) {
	message := make([]byte, 249)
	for i, b := range blocksizes {
		for j, m := range msglengths {
			msg := message[:m]

			generateSequence(msg, uint32((m+b)*i))

			pkcs7 := NewPKCS7(b)
			pad := pkcs7.Pad(msg)

			if expected := len(msg) + pkcs7.Overhead(msg); expected != len(pad) {
				t.Fatalf("Block: %d Message: %d\nOverhead failed: Found: %d Expected: %d", i, j, len(pad), expected)
			}
			if len(pad)%b != 0 {
				t.Fatalf("Block: %d Message: %d\nPadded block not a multiply of blocksize %d", i, j, len(pad))
			}

			unpad, err := pkcs7.Unpad(pad)
			if err != nil {
				t.Fatalf("Block: %d Message: %d\nUnpad failed: %s", i, j, err)
			}
			if !bytes.Equal(msg, unpad) {
				t.Fatalf("Block: %d Message: %d\nUnpad does not produces orginal msg", i, j)
			}

			padBytes := pad[len(msg):]
			for _, v := range padBytes {
				if int(v) != len(pad)-len(msg) {
					t.Fatalf("Block: %d Message: %d\nPKCS7 does not use PKCS7-Padding scheme", i, j)
				}
			}
		}
	}
}

func TestX923(t *testing.T) {
	message := make([]byte, 249)
	for i, b := range blocksizes {
		for j, m := range msglengths {
			msg := message[:m]

			generateSequence(msg, uint32((m+b)*i))

			x923 := NewX923(b)
			pad := x923.Pad(msg)

			if expected := len(msg) + x923.Overhead(msg); expected != len(pad) {
				t.Fatalf("Block: %d Message: %d\nOverhead failed: Found: %d Expected: %d", i, j, len(pad), expected)
			}
			if len(pad)%b != 0 {
				t.Fatalf("Block: %d Message: %d\nPadded block not a multiply of blocksize %d", i, j, len(pad))
			}

			unpad, err := x923.Unpad(pad)
			if err != nil {
				t.Fatalf("Block: %d Message: %d\nUnpad failed: %s", i, j, err)
			}
			if !bytes.Equal(msg, unpad) {
				t.Fatalf("Block: %d Message: %d\nUnpad does not produces orginal msg", i, j)
			}

			padBytes := pad[len(msg) : len(pad)-1]
			for _, v := range padBytes {
				if int(v) != 0 {
					t.Fatalf("Block: %d Message: %d\nX923 does not use X923-Padding scheme", i, j)
				}
			}
			if int(pad[len(pad)-1]) != len(pad)-len(msg) {
				t.Fatalf("Block: %d Message: %d\nX923 does not use X923-Padding scheme for last byte", i, j)
			}
		}
	}
}

func TestISO10126(t *testing.T) {
	message := make([]byte, 249)
	for i, b := range blocksizes {
		for j, m := range msglengths {
			msg := message[:m]

			generateSequence(msg, uint32((m+b)*i))

			iso := NewISO10126(b, rand.Reader)
			pad := iso.Pad(msg)

			if expected := len(msg) + iso.Overhead(msg); expected != len(pad) {
				t.Fatalf("Block: %d Message: %d\nOverhead failed: Found: %d Expected: %d", i, j, len(pad), expected)
			}
			if len(pad)%b != 0 {
				t.Fatalf("Block: %d Message: %d\nPadded block not a multiply of blocksize %d", i, j, len(pad))
			}

			unpad, err := iso.Unpad(pad)
			if err != nil {
				t.Fatalf("Block: %d Message: %d\nUnpad failed: %s", i, j, err)
			}
			if !bytes.Equal(msg, unpad) {
				t.Fatalf("Block: %d Message: %d\nUnpad does not produces orginal msg", i, j)
			}

			if int(pad[len(pad)-1]) != len(pad)-len(msg) {
				t.Fatalf("Block: %d Message: %d\nISO10126 does not use ISO10126-Padding scheme for last byte", i, j)
			}
		}
	}
}
