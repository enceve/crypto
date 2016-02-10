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
	return "pad: illegal padding length: " + strconv.Itoa(int(p))
}

// A ByteError indicates, that at least one byte
// of the padded block is not correct.
type ByteError int

func (p ByteError) Error() string {
	return "pad: illegal padding byte: " + strconv.Itoa(int(p))
}

// The Padding interface represents a padding scheme.
type Padding interface {
	// Calculates the padding overhead.
	// The block argument is the unpadded block.
	// The size argument is the size of a full block.
	// The overhead is defined through:
	// len(paddedBlock) - len(unpaddedBlock)
	// E.g. the size argument is 16 and the length of the
	// block argument is 12 - than the overhead will be 4.
	Overhead(block []byte, size int) uint

	// Expands an unpadded block (the block argument) to a
	// block with the length of the size argument.
	// This function returns a padded block (the size of the
	// returned slice may be greater than the size argument).
	// If len(block) is greater than the size argument, this
	// function panics.
	Pad(block []byte, size int) []byte

	// Removes the padding bytes from the given block argument.
	// If the padding is somehow incorrect this function returns
	// an nil for the slice and an error. The returned slice is
	// the unpadded block. If the padding could removed successfully
	// the returned error is nil.
	// The len(block) must be equal to the size argument!
	Unpad(block []byte, size int) ([]byte, error)
}

// Creates a new Padding implementing the ANSI X.923 scheme.
func NewX923() Padding {
	pad := x923Padding(0)
	return pad
}

// Creates a new Padding implementing the PKCS 7 scheme.
func NewPkcs7() Padding {
	pad := pkcs7Padding(0)
	return pad
}

// Creates a new Padding, which uses the padding scheme
// described in ISO 10126. The padding bytes are taken
// form the given rand argument. This reader should return
// random data.
func NewRandom(rand io.Reader) Padding {
	pad := &randomPadding{
		random: rand,
	}
	return pad
}
