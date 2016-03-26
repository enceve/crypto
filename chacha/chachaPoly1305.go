// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package chacha

import (
	"crypto/cipher"
	"crypto/subtle"
	"github.com/EncEve/crypto"
	"golang.org/x/crypto/poly1305"
)

// The AEAD cipher ChaCha20-Poly1305
type aeadCipher struct {
	key [32]byte
}

// NewAEAD creates a new cipher implementing the
// ChaCha20-Poly1305 construction specified in
// RFC 7539. The key argument must be 256 bit
// (32 byte) - otherwise a non-nil error is
// returned.
func NewAEAD(key []byte) (cipher.AEAD, error) {
	if k := len(key); k != 32 {
		return nil, crypto.KeySizeError(k)
	}
	c := new(aeadCipher)
	for i, v := range key {
		c.key[i] = v
	}
	return c, nil
}

func (c *aeadCipher) Overhead() int { return poly1305.TagSize }

func (c *aeadCipher) NonceSize() int { return NonceSize }

func (c *aeadCipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if n := len(nonce); n != NonceSize {
		panic(crypto.NonceSizeError(n))
	}
	if len(dst) < len(plaintext) {
		panic("dst buffer to small")
	}

	// create the ploy1305 key
	var polyKey [32]byte
	var tmp [64]byte
	XORKeyStream(tmp[:], c.key[:], nonce, 0, tmp[:])
	copy(polyKey[:], tmp[:32])

	// encrypt the plaintext
	n := len(plaintext)
	XORKeyStream(dst, c.key[:], nonce, 1, plaintext)

	// authenticate the ciphertext
	tag := authenticate(&polyKey, dst[:n], additionalData)
	return append(dst[:n], tag...)
}

func (c *aeadCipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if n := len(nonce); n != NonceSize {
		return nil, crypto.NonceSizeError(n)
	}
	if len(ciphertext) < poly1305.TagSize {
		return nil, crypto.AuthenticationError{}
	}
	if len(dst) < len(ciphertext)-poly1305.TagSize {
		panic("dst buffer to small")
	}

	hash := ciphertext[len(ciphertext)-poly1305.TagSize:]
	ciphertext = ciphertext[:len(ciphertext)-poly1305.TagSize]

	// create the ploy1305 key
	var polyKey [32]byte
	var tmp [64]byte
	XORKeyStream(tmp[:], c.key[:], nonce, 0, tmp[:])
	copy(polyKey[:], tmp[:32])

	// authenticate the ciphertext
	tag := authenticate(&polyKey, ciphertext, additionalData)
	if subtle.ConstantTimeCompare(tag, hash) != 1 {
		return nil, crypto.AuthenticationError{}
	}

	// decrypt ciphertext
	XORKeyStream(dst, c.key[:], nonce, 1, ciphertext)
	return dst[:len(ciphertext)], nil
}

// authenticate calculates the poly1305 tag from
// the given ciphertext and additional data.
//
// TODO (EncEve): another poly1305 implementation
// 		  (which satisfy the Writer interface)
//		  may avoids buffer allocation and copying.
func authenticate(key *[32]byte, ciphertext, additionalData []byte) []byte {
	ctLen := uint64(len(ciphertext))
	adLen := uint64(len(additionalData))
	padAD, padCT := adLen%16, ctLen%16

	bufSize := adLen + ctLen + 16
	if padAD > 0 {
		bufSize += 16 - padAD
	}
	if padCT > 0 {
		bufSize += 16 - padCT
	}
	buf := make([]byte, bufSize)
	off := copy(buf, additionalData)
	off += copy(buf[off:], make([]byte, 16-padAD))
	off += copy(buf[off:], ciphertext)
	off += copy(buf[off:], make([]byte, 16-padCT))

	buf[off+0] = byte(adLen)
	buf[off+1] = byte(adLen >> 8)
	buf[off+2] = byte(adLen >> 16)
	buf[off+3] = byte(adLen >> 24)
	buf[off+4] = byte(adLen >> 32)
	buf[off+5] = byte(adLen >> 40)
	buf[off+6] = byte(adLen >> 48)
	buf[off+7] = byte(adLen >> 56)
	off += 8
	buf[off+0] = byte(ctLen)
	buf[off+1] = byte(ctLen >> 8)
	buf[off+2] = byte(ctLen >> 16)
	buf[off+3] = byte(ctLen >> 24)
	buf[off+4] = byte(ctLen >> 32)
	buf[off+5] = byte(ctLen >> 40)
	buf[off+6] = byte(ctLen >> 48)
	buf[off+7] = byte(ctLen >> 56)

	var tag [poly1305.TagSize]byte
	poly1305.Sum(&tag, buf, key)
	return tag[:]
}
