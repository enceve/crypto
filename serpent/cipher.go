// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The serpent package implements the Serpent block cipher
// submitted to the AES challenge. Serpent was designed by
// Ross Anderson, Eli Biham und Lars Knudsen.
// The block cipher takes a 128, 192 or 256 bit key and
// has a block size of 128 bit.
package serpent

import (
	"crypto/cipher"

	"github.com/EncEve/crypto"
)

const (
	BlockSize = 16         // The Serpent block size in bytes.
	phi       = 0x9e3779b9 // The Serpent phi constant (sqrt(5) - 1) * 2**31
)

// A serpentCipher struct holds an array of 132 32 bit values.
// These are the sub-keys created by the keySchedule function
type serpentCipher struct {
	sk [132]uint32
}

// New returns a new cipher.Block implementing the serpent block cipher.
// The key argument must be 128, 192 or 256 bit (16, 24, 32 byte).
func New(key []byte) (cipher.Block, error) {
	if k := len(key); k != 16 && k != 24 && k != 32 {
		return nil, crypto.KeySizeError(k)
	}
	s := &serpentCipher{}
	keySchedule(key, &s.sk)
	return s, nil
}

func (s *serpentCipher) BlockSize() int { return BlockSize }

func (s *serpentCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("dst buffer to small")
	}
	encryptBlock(dst, src, &s.sk)
}

func (s *serpentCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("dst buffer to small")
	}
	decryptBlock(dst, src, &s.sk)
}
