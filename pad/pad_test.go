package pad

import (
	"crypto/rand"
	"testing"
)

const blockSize = 16

var paddings = []Padding{
	NewX923(),
	NewPkcs7(),
	NewRandom(rand.Reader),
}

func TestPadding(t *testing.T) {
	partBlock := make([]byte, blockSize-3)
	fullBlock := make([]byte, blockSize)

	for _, pad := range paddings {
		generalPaddingTest(t, pad, partBlock, fullBlock)
	}
}

func generalPaddingTest(t *testing.T, p Padding, partBlock, fullBlock []byte) {
	if o := p.Overhead(partBlock, blockSize); o != 3 {
		t.Fatalf("pad: Expected overhead of 3 but found %d", o)
	}
	if o := p.Overhead(fullBlock, blockSize); o != 2*blockSize {
		t.Fatalf("pad: Expected overhead of %d but found %d", (2 * blockSize), o)
	}

	padBlock := p.Pad(partBlock, blockSize)
	if len(padBlock) != blockSize {
		t.Fatal("pad: padded block has not the given blocksize")
	}
	unpadBlock, err := p.Unpad(padBlock, blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(unpadBlock) != len(partBlock) {
		t.Fatal("pad: length of unpadded block differs form the original")
	}
	padBlock = p.Pad(fullBlock, blockSize)
	if len(padBlock) != 2*blockSize {
		t.Fatal("pad: length of padded full block is not twice the blocksize")
	}
	unpadBlock, err = p.Unpad(padBlock[blockSize:], blockSize)
	if err != nil {
		t.Fatal(err)
	}
	if len(unpadBlock) != 0 {
		t.Fatal("pad: length of unpadded full block is not 0")
	}
}
