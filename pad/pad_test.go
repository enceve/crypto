// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package pad

import (
	"crypto/rand"
	"testing"
)

const blocksize = 16

var paddings []Padding = []Padding{
	NewPkcs7(blocksize),
	NewX923(blocksize),
	NewIso10126(blocksize, rand.Reader),
}

func TestPKCS7(t *testing.T) {
	p := NewPkcs7(blocksize)
	padded := p.Pad(make([]byte, blocksize-4))
	for i := blocksize - 4; i < blocksize; i++ {
		if padded[i] != 4 {
			t.Fatal("PKCS 7 padding failed while padding a block")
		}
	}
	_, err := p.Unpad(padded)
	if err != nil {
		t.Fatal(err)
	}
}

func TestX923(t *testing.T) {
	p := NewX923(blocksize)
	padded := p.Pad(make([]byte, blocksize-4))
	for i := blocksize - 4; i < blocksize-1; i++ {
		if padded[i] != 0 {
			t.Fatal("ANSI X923 padding failed while padding a block")
		}
	}
	_, err := p.Unpad(padded)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCommon(t *testing.T) {
	for i := range paddings {
		generalPaddingTest(t, paddings[i])
	}
}

func generalPaddingTest(t *testing.T, p Padding) {
	empty := make([]byte, 0)
	partEmpty := make([]byte, blocksize-3)
	full := make([]byte, blocksize)
	partLarge := make([]byte, 3*blocksize+5)
	large := make([]byte, 3*blocksize)

	// overhead test
	overheadTest(t, p, empty, blocksize)
	overheadTest(t, p, partEmpty, 3)
	overheadTest(t, p, full, blocksize)
	overheadTest(t, p, partLarge, blocksize-5)
	overheadTest(t, p, large, blocksize)

	// pad test

	paddedEmpty := padTest(t, p, empty)
	paddedPartEmpty := padTest(t, p, partEmpty)
	paddedFull := padTest(t, p, full)
	paddedPartLarge := padTest(t, p, partLarge)
	paddedLarge := padTest(t, p, large)

	// unpad test
	unpadTest(t, p, paddedEmpty)
	unpadTest(t, p, paddedPartEmpty)
	unpadTest(t, p, paddedFull)
	unpadTest(t, p, paddedPartLarge)
	unpadTest(t, p, paddedLarge)
}

func overheadTest(t *testing.T, p Padding, src []byte, expOverhead int) {
	overhead := p.Overhead(src)
	if overhead != expOverhead {
		t.Fatalf("%s : overhead does not match expected overhead: found %d , expected %d", p, overhead, expOverhead)
	}
}

func padTest(t *testing.T, p Padding, src []byte) []byte {
	padded := p.Pad(src)
	if len(padded)%blocksize != 0 {
		t.Fatalf("%s : length of padded slice is not a multiply the blocksize", p)
		t.FailNow()
	}
	if len(padded) != p.Overhead(src)+len(src) {
		t.Fatalf("%s : length of padded slice is not a src length + overhead", p)
		t.FailNow()
	}
	return padded
}

func unpadTest(t *testing.T, p Padding, src []byte) {
	_, err := p.Unpad(src)
	if err != nil {
		t.Fatalf("%s : %s", p, err)
	}
}
