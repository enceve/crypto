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

const BlockSize = 16 // The Serpent block size in bytes.

// New returns a new cipher.Block implementing the serpent block cipher.
// The key argument must be 128, 192 or 256 bit (16, 24, 32 byte).
func NewCipher(key []byte) (cipher.Block, error) {
	if k := len(key); k != 16 && k != 24 && k != 32 {
		return nil, crypto.KeySizeError(k)
	}
	s := &blockCipher{}
	keySchedule(key, &s.sk)
	return s, nil
}

// The blockCipher struct holds an array of 132 32 bit values.
// These are the sub-keys created by the keySchedule function.
type blockCipher struct {
	sk [132]uint32
}

func (s *blockCipher) BlockSize() int { return BlockSize }

func (s *blockCipher) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("dst buffer to small")
	}
	encryptBlock(dst, src, &s.sk)
}

func (s *blockCipher) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("dst buffer to small")
	}
	decryptBlock(dst, src, &s.sk)
}
