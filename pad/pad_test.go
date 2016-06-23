// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package pad

import (
	"bytes"
	"crypto/rand"
	"strconv"
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

var recoverFail = func(t *testing.T, s string) {
	if err := recover(); err == nil {
		t.Fatalf("Function: %s\nRecover expected error, but no one occured", s)
	}
}

func TestNewPKCS7(t *testing.T) {
	fail := func(blocksize int) {
		defer recoverFail(t, "NewPKCS7 with blocksize: "+strconv.Itoa(blocksize)+" failed")
		NewPKCS7(blocksize)
	}

	fail(0)
	fail(256)
}

func TestNewX923(t *testing.T) {
	fail := func(blocksize int) {
		defer recoverFail(t, "NewX923 with blocksize: "+strconv.Itoa(blocksize)+" failed")
		NewX923(blocksize)
	}

	fail(0)
	fail(256)
}

func TestNewISO10126(t *testing.T) {
	fail := func(blocksize int) {
		defer recoverFail(t, "NewISO10126 with blocksize: "+strconv.Itoa(blocksize)+" failed")
		NewISO10126(blocksize, nil)
	}

	fail(0)
	fail(256)
}

func TestUnpadPKCS7(t *testing.T) {
	p := NewPKCS7(16)

	if _, err := p.Unpad(make([]byte, p.BlockSize()-1)); err == nil {
		t.Fatal("Incomplete block not rejected by PKCS7")
	}
	if _, err := p.Unpad(make([]byte, p.BlockSize()+1)); err == nil {
		t.Fatal("Incomplete block not rejected by PKCS7")
	}

	block := make([]byte, p.BlockSize())
	if _, err := p.Unpad(block); err == nil {
		t.Fatal("Block of zeros not rejected by PKCS7")
	}

	block[len(block)-1] = byte(p.BlockSize() - 1)
	if _, err := p.Unpad(block); err == nil {
		t.Fatal("Invalid padding not rejected by PKCS7")
	}
	block[len(block)-1] = byte(p.BlockSize() + 1)
	if _, err := p.Unpad(block); err == nil {
		t.Fatal("Invalid padding not rejected by PKCS7")
	}
}

func TestUnpadX923(t *testing.T) {
	p := NewX923(16)

	if _, err := p.Unpad(make([]byte, p.BlockSize()-1)); err == nil {
		t.Fatal("Incomplete block not rejected by X923")
	}
	if _, err := p.Unpad(make([]byte, p.BlockSize()+1)); err == nil {
		t.Fatal("Incomplete block not rejected by X923")
	}

	block := make([]byte, p.BlockSize())
	if _, err := p.Unpad(block); err == nil {
		t.Fatal("Block of zeros not rejected by X923")
	}

	block[len(block)-1] = byte(p.BlockSize() - 1)
	block[1] = 1
	if _, err := p.Unpad(block); err == nil {
		t.Fatal("Invalid padding not rejected by X923")
	}
	block[len(block)-1] = byte(p.BlockSize() + 1)
	if _, err := p.Unpad(block); err == nil {
		t.Fatal("Invalid padding not rejected by X923")
	}
}

func TestUnpadISO10126(t *testing.T) {
	p := NewISO10126(16, nil)

	if _, err := p.Unpad(make([]byte, p.BlockSize()-1)); err == nil {
		t.Fatal("Incomplete block not rejected by ISO10126")
	}
	if _, err := p.Unpad(make([]byte, p.BlockSize()+1)); err == nil {
		t.Fatal("Incomplete block not rejected by ISO10126")
	}

	block := make([]byte, p.BlockSize())
	if _, err := p.Unpad(block); err == nil {
		t.Fatal("Block of zeros not rejected by ISO10126")
	}

	block[len(block)-1] = byte(p.BlockSize() + 1)
	if _, err := p.Unpad(block); err == nil {
		t.Fatal("Invalid padding not rejected by ISO10126")
	}
}
