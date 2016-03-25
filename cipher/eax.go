// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package cipher implements additional block cipher modes
// that can be wrapped around low-level block cipher implementations.
// For standard block cipher modes see: https://golang.org/pkg/crypto/cipher
package cipher

import (
	"crypto/cipher"
	"crypto/subtle"
	"github.com/EncEve/crypto"
	"github.com/EncEve/crypto/cmac"
	"hash"
)

const (
	nTag = 0x0 // The nonce tag constant
	hTag = 0x1 // The additional data tag constant
	cTag = 0x2 // The ciphertext tag constant
)

// The EAX cipher
type eaxCipher struct {
	block    cipher.Block
	ctr, buf []byte
	mac      hash.Hash
}

// NewEAX returns the given block cipher wrapped in EAX Mode.
// EAX is a two pass-scheme AEAD cipher with provable security.
// For authentication EAX uses CMac (OMAC1).
// This implementations produces authentication tags with the same
// size as the block size of the cipher.
// This function returns a non-nil error if the given block cipher
// is not supported by CMac (see crypto/cmac for details)
func NewEAX(c cipher.Block) (cipher.AEAD, error) {
	if c == nil {
		panic("c is nil")
	}
	m, err := cmac.New(c)
	if err != nil {
		return nil, err
	}
	return &eaxCipher{
		block: c,
		mac:   m,
		ctr:   make([]byte, c.BlockSize()),
		buf:   make([]byte, c.BlockSize()),
	}, nil
}

func (c *eaxCipher) NonceSize() int { return c.block.BlockSize() }

func (c *eaxCipher) Overhead() int { return c.mac.Size() }

func (c *eaxCipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != c.block.BlockSize() {
		panic("invalid nonce for EAX - nonce length must be equal to block size")
	}
	if len(dst) < len(plaintext) {
		panic("dst buffer to small")
	}

	tag := make([]byte, c.mac.BlockSize())

	// process nonce
	tag[len(tag)-1] = nTag
	c.mac.Write(tag)
	c.mac.Write(nonce)
	authNonce := c.mac.Sum(nil)
	c.mac.Reset()

	// process additional data
	tag[len(tag)-1] = hTag
	c.mac.Write(tag)
	c.mac.Write(additionalData)
	authData := c.mac.Sum(nil)
	c.mac.Reset()

	// encrypt
	n := len(plaintext)
	copy(c.ctr, authNonce) // set the ctr-mode nonce
	c.ctrCrypt(dst, plaintext)

	// process ciphertext
	tag[len(tag)-1] = cTag
	c.mac.Write(tag)
	c.mac.Write(dst[:n])
	tag = c.mac.Sum(tag[:0])
	c.mac.Reset()

	for i := range tag {
		tag[i] ^= authData[i] ^ authNonce[i]
	}
	return append(dst[:n], tag...)
}

func (c *eaxCipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != c.block.BlockSize() {
		panic("invalid nonce for EAX - nonce length must be equal to block size")
	}
	if len(ciphertext) < c.mac.Size() {
		return nil, crypto.AuthenticationError{}
	}

	authTag := ciphertext[len(ciphertext)-c.mac.Size():]
	ciphertext = ciphertext[:len(ciphertext)-len(authTag)]

	tag := make([]byte, c.mac.BlockSize())

	// process nonce
	tag[len(tag)-1] = nTag
	c.mac.Write(tag)
	c.mac.Write(nonce)
	authNonce := c.mac.Sum(nil)
	c.mac.Reset()

	// process additional data
	tag[len(tag)-1] = hTag
	c.mac.Write(tag)
	c.mac.Write(additionalData)
	authData := c.mac.Sum(nil)
	c.mac.Reset()

	// process ciphertext
	tag[len(tag)-1] = cTag
	c.mac.Write(tag)
	c.mac.Write(ciphertext)
	tag = c.mac.Sum(tag[:0])
	c.mac.Reset()

	for i := range tag {
		tag[i] ^= authData[i] ^ authNonce[i]
	}

	if subtle.ConstantTimeCompare(tag, authTag) != 1 {
		return nil, crypto.AuthenticationError{}
	}

	// decrypt
	n := len(ciphertext)
	copy(c.ctr, authNonce) // set the ctr-mode nonce
	c.ctrCrypt(dst, ciphertext)

	return dst[:n], nil
}

// encrypts the bytes in src with the CTR mode and writes
// the ciphertext into dst
func (c *eaxCipher) ctrCrypt(dst, src []byte) {
	length := len(src)
	bs := c.block.BlockSize()
	n := length - (length % bs)

	for i := 0; i < n; i += bs {
		j := i + bs
		c.block.Encrypt(c.buf, c.ctr)
		crypto.XOR(dst[i:j], src[i:j], c.buf)

		// Increment counter
		for k := len(c.ctr) - 1; k >= 0; k-- {
			c.ctr[k]++
			if c.ctr[k] != 0 {
				break
			}
		}
	}
	if n < length {
		c.block.Encrypt(c.buf, c.ctr)
		crypto.XOR(dst[n:], src[n:], c.buf)
	}
	// no reset of ctr needed - Seal or Open does this for us
}
