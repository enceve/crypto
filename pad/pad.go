// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The package pad implements some padding schemes
// for block ciphers.
package pad

import (
	"io"
	"strconv"
)

// A LengthError indicates, that the length of
// the padding is not correct.
type LengthError int

func (p LengthError) Error() string {
	return "illegal padding length: " + strconv.Itoa(int(p))
}

// A ByteError indicates, that at least one byte
// of the padded block is not correct.
type ByteError int

func (p ByteError) Error() string {
	return "illegal padding byte: " + strconv.Itoa(int(p))
}

// The Padding interface represents a padding scheme.
type Padding interface {

	// BlockSize returns the block size for which
	// the padding can be used.
	BlockSize() int

	// Returns the overhead, the padding will cause
	// by padding the given byte slice. The overhead
	// will always be between 1 and BlockSize() inclusively.
	Overhead(src []byte) int

	// Pads the last (may incomplete) block of the src slice
	// to a padded and complete block, appends the padding bytes
	// to the src slice and returns this slice.
	// The length of the returned slice is len(src) + Overhead(src)
	Pad(src []byte) []byte

	// Takes a slice and tries to remove the padding bytes
	// form the last block. Therefore the length of the
	// src argument must be a multiply of the blocksize.
	// If the returned error is nil, the padding could be
	// removed successfully. The returned slice holds the
	// unpadded src bytes.
	Unpad(src []byte) ([]byte, error)
}

// Returns a new Padding implementing the ANSI X.923 scheme.
// Only block sizes between 1 and 255 are legal.
// This function panics if the blocksize is smaller than 1
// or greater than 255.
func NewX923(blocksize int) Padding {
	if blocksize < 1 || blocksize > 255 {
		panic("illegal blocksize - size must between 0 and 256")
	}
	pad := x923Padding(blocksize)
	return pad
}

// Returns a new Padding implementing the PKCS 7 scheme.
// Only block sizes between 1 and 255 are legal.
// This function panics if the blocksize is smaller than 1
// or greater than 255.
func NewPkcs7(blocksize int) Padding {
	if blocksize < 1 || blocksize > 255 {
		panic("illegal blocksize - size must between 0 and 256")
	}
	pad := pkcs7Padding(blocksize)
	return pad
}

// Returns a new Padding, which uses the padding scheme
// described in ISO 10126. The padding bytes are taken
// form the given rand argument. This reader should return
// random data.
// Only block sizes between 1 and 255 are legal.
// This function panics if the blocksize is smaller than 1
// or greater than 255.
func NewIso10126(blocksize int, rand io.Reader) Padding {
	if blocksize < 1 || blocksize > 255 {
		panic("illegal blocksize - size must between 0 and 256")
	}
	pad := &isoPadding{
		random: rand,
	}
	pad.blocksize = blocksize
	return pad
}

// Utility functions

// Returns the overhead for a given slice with a
// specific block size.
func generalOverhead(blocksize int, src []byte) int {
	return blocksize - (len(src) % blocksize)
}
