// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package chacha implements some low level functions of the
// ChaCha cipher family.
package chacha

var constants = [4]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

// Cipher is the ChaCha/X struct.
// X is the number of rounds (e.g. ChaCha20 for 20 rounds)
type Cipher struct {
	state  [16]uint32
	block  [64]byte
	off    int
	rounds int
}

// Sets the counter of the cipher.
func (c *Cipher) SetCounter(ctr uint32) {
	c.state[12] = ctr
}
