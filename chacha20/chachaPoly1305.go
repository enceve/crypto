// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package chacha20

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/enceve/crypto"
	"github.com/enceve/crypto/poly1305"
)

// The max. size of the auth. tag for the ChaCha20Poly1305 AEAD cipher in bytes.
const TagSize = poly1305.TagSize

// NewAEAD returns a cipher.AEAD implementing the
// ChaCha20Poly1305 construction specified in
// RFC 7539 with arbitrary tag size. The tagsize must be
// between 1 and the TagSize constant.
func NewAEAD(key *[32]byte, tagsize int) (cipher.AEAD, error) {
	if tagsize < 1 || tagsize > TagSize {
		return nil, errors.New("tag size must be between 1 and 16")
	}
	c := &aead{tagsize: tagsize}
	c.key = *key
	return c, nil
}

// The AEAD cipher ChaCha20-Poly1305
type aead struct {
	key     [32]byte
	tagsize int
}

func (c *aead) Overhead() int { return c.tagsize }

func (c *aead) NonceSize() int { return NonceSize }

func (c *aead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if n := len(nonce); n != NonceSize {
		panic(crypto.NonceSizeError(n))
	}
	if len(dst) < len(plaintext)+c.tagsize {
		panic("dst buffer to small")
	}
	var Nonce [12]byte
	copy(Nonce[:], nonce)

	// create the poly1305 key
	var polyKey [32]byte
	XORKeyStream(polyKey[:], polyKey[:], &Nonce, &(c.key), 0)

	// encrypt the plaintext
	n := len(plaintext)
	XORKeyStream(dst, plaintext, &Nonce, &(c.key), 1)

	// authenticate the ciphertext
	tag := authenticate(&polyKey, dst[:n], additionalData)
	return append(dst[:n], tag[:c.tagsize]...)
}

func (c *aead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if n := len(nonce); n != NonceSize {
		return nil, crypto.NonceSizeError(n)
	}
	if len(ciphertext) < c.tagsize {
		return nil, crypto.AuthenticationError{}
	}
	if len(dst) < len(ciphertext)-c.tagsize {
		panic("dst buffer to small")
	}
	var Nonce [12]byte
	copy(Nonce[:], nonce)

	hash := ciphertext[len(ciphertext)-c.tagsize:]
	ciphertext = ciphertext[:len(ciphertext)-c.tagsize]

	// create the poly1305 key
	var polyKey [32]byte
	XORKeyStream(polyKey[:], polyKey[:], &Nonce, &(c.key), 0)

	// authenticate the ciphertext
	tag := authenticate(&polyKey, ciphertext, additionalData)
	if subtle.ConstantTimeCompare(tag[:c.tagsize], hash[:c.tagsize]) != 1 {
		return nil, crypto.AuthenticationError{}
	}

	// decrypt ciphertext
	XORKeyStream(dst, ciphertext, &Nonce, &(c.key), 1)
	return dst[:len(ciphertext)], nil
}

// authenticate calculates the poly1305 tag from
// the given ciphertext and additional data.
func authenticate(key *[32]byte, ciphertext, additionalData []byte) []byte {
	ctLen := uint64(len(ciphertext))
	adLen := uint64(len(additionalData))
	padAD, padCT := adLen%16, ctLen%16

	var buf [16]byte
	buf[0] = byte(adLen)
	buf[1] = byte(adLen >> 8)
	buf[2] = byte(adLen >> 16)
	buf[3] = byte(adLen >> 24)
	buf[4] = byte(adLen >> 32)
	buf[5] = byte(adLen >> 40)
	buf[6] = byte(adLen >> 48)
	buf[7] = byte(adLen >> 56)
	buf[8] = byte(ctLen)
	buf[9] = byte(ctLen >> 8)
	buf[10] = byte(ctLen >> 16)
	buf[11] = byte(ctLen >> 24)
	buf[12] = byte(ctLen >> 32)
	buf[13] = byte(ctLen >> 40)
	buf[14] = byte(ctLen >> 48)
	buf[15] = byte(ctLen >> 56)

	poly, _ := poly1305.New(key[:])
	poly.Write(additionalData)
	if padAD > 0 {
		poly.Write(make([]byte, 16-padAD))
	}
	poly.Write(ciphertext)
	if padCT > 0 {
		poly.Write(make([]byte, 16-padCT))
	}
	poly.Write(buf[:])
	return poly.Sum(nil)
}
