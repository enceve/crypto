// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The chacha package implements D J Bernstein's Chacha20 stream cipher algorithm
// and the ChaCha20-Poly1305 AEAD construction described in RFC 7539. Notice that
// this implementation of ChaCha20 can only process 64 x 2^32 bytes (256 GB)
// for one specific key and nonce combination.
package chacha

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"

	"github.com/EncEve/crypto"
	"github.com/EncEve/crypto/poly1305"
)

const (
	NonceSize = 12               // The size of the nonce for ChaCha20 in bytes.
	TagSize   = poly1305.TagSize // The max. size of the auth. tag for the ChaCha-Poly1305 AEAD cipher in bytes.
)

// XORKeyStream xor`s each byte in the given src with a byte from the
// ChaCha20 key stream. The nonce must be unique for one key for all
// time. If len(dst) < len(src), XORKeyStream panics. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
func XORKeyStream(dst, src []byte, key *[32]byte, nonce *[12]byte, counter uint32) {
	genericXORKeyStream(dst, src, key, nonce, counter, 20)
}

// XORKeyStream12 xor`s each byte in the given src with a byte from the
// ChaCha20-12 key stream. The nonce must be unique for one key for all
// time. If len(dst) < len(src), XORKeyStream panics. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
func XORKeyStream12(dst, src []byte, key *[32]byte, nonce *[12]byte, counter uint32) {
	genericXORKeyStream(dst, src, key, nonce, counter, 12)
}

// XORKeyStream8 xor`s each byte in the given src with a byte from the
// ChaCha20-8 key stream. The nonce must be unique for one key for all
// time. If len(dst) < len(src), XORKeyStream panics. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
func XORKeyStream8(dst, src []byte, key *[32]byte, nonce *[12]byte, counter uint32) {
	genericXORKeyStream(dst, src, key, nonce, counter, 8)
}

// New returns a new cipher.Stream implementing the ChaCha20
// cipher. The key must be exactly 256 bit (32 byte). The
// nonce must be exactly 96 bit (12 byte) and unique for one
// key for all time.
func NewCipher(key, nonce []byte) (cipher.Stream, error) {
	if k := len(key); k != 32 {
		return nil, crypto.KeySizeError(k)
	}
	if n := len(nonce); n != NonceSize {
		return nil, crypto.NonceSizeError(n)
	}
	var k [32]byte
	var n [12]byte
	copy(k[:], key)
	copy(n[:], nonce)

	c := &chacha20{}
	initialize(&k, &n, &(c.state))
	return c, nil
}

// NewAEAD returns a cipher.AEAD implementing the
// ChaCha20-Poly1305 construction specified in
// RFC 7539 with arbitrary tag size. The key argument
// must be 256 bit (32 byte), and the tagSize must be
// between 1 and 16.
func NewAEAD(key []byte, tagSize int) (cipher.AEAD, error) {
	if k := len(key); k != 32 {
		return nil, crypto.KeySizeError(k)
	}
	if tagSize < 1 || tagSize > TagSize {
		return nil, errors.New("tag size must be between 1 and 16")
	}
	c := &aeadCipher{tagSize: tagSize}
	for i, v := range key {
		c.key[i] = v
	}
	return c, nil
}

// The ChaCha20 stream cipher
type chacha20 struct {
	state  [16]uint32
	stream [64]byte
	off    int
}

func (c *chacha20) XORKeyStream(dst, src []byte) {
	length := len(src)
	if len(dst) < length {
		panic("dst buffer to small")
	}
	if c.off > 0 {
		left := 64 - c.off
		if left > length {
			left = length
		}
		for i := 0; i < left; i++ {
			dst[i] = src[i] ^ c.stream[c.off+i]
		}
		src = src[left:]
		dst = dst[left:]
		length -= left
		c.off += left
		if c.off == 64 {
			c.off = 0
		}
	}

	n := length - (length % 64)
	for i := 0; i < n; i += 64 {
		chachaCore(&(c.stream), &(c.state), 20)
		c.state[12]++ // inc. counter
		for j := range c.stream {
			dst[i+j] = src[i+j] ^ c.stream[j]
		}
	}
	if n < length {
		chachaCore(&(c.stream), &(c.state), 20)
		c.state[12]++ // inc. counter
		for j, v := range c.stream[:length-n] {
			dst[n+j] = src[n+j] ^ v
		}
		c.off += (length - n)
	}
}

// The AEAD cipher ChaCha20-Poly1305
type aeadCipher struct {
	key     [32]byte
	tagSize int
}

func (c *aeadCipher) Overhead() int { return c.tagSize }

func (c *aeadCipher) NonceSize() int { return NonceSize }

func (c *aeadCipher) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if n := len(nonce); n != NonceSize {
		panic(crypto.NonceSizeError(n))
	}
	if len(dst) < len(plaintext)+c.tagSize {
		panic("dst buffer to small")
	}
	var Nonce [12]byte
	copy(Nonce[:], nonce)

	// create the poly1305 key
	var polyKey [32]byte
	XORKeyStream(polyKey[:], polyKey[:], &(c.key), &Nonce, 0)

	// encrypt the plaintext
	n := len(plaintext)
	XORKeyStream(dst, plaintext, &(c.key), &Nonce, 1)

	// authenticate the ciphertext
	tag := authenticate(&polyKey, dst[:n], additionalData)
	return append(dst[:n], tag[0:c.tagSize]...)
}

func (c *aeadCipher) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if n := len(nonce); n != NonceSize {
		return nil, crypto.NonceSizeError(n)
	}
	if len(ciphertext) < c.tagSize {
		return nil, crypto.AuthenticationError{}
	}
	if len(dst) < len(ciphertext)-c.tagSize {
		panic("dst buffer to small")
	}
	var Nonce [12]byte
	copy(Nonce[:], nonce)

	hash := ciphertext[len(ciphertext)-c.tagSize:]
	ciphertext = ciphertext[:len(ciphertext)-c.tagSize]

	// create the poly1305 key
	var polyKey [32]byte
	XORKeyStream(polyKey[:], polyKey[:], &(c.key), &Nonce, 0)

	// authenticate the ciphertext
	tag := authenticate(&polyKey, ciphertext, additionalData)
	if subtle.ConstantTimeCompare(tag[:c.tagSize], hash[:c.tagSize]) != 1 {
		return nil, crypto.AuthenticationError{}
	}

	// decrypt ciphertext
	XORKeyStream(dst, ciphertext, &(c.key), &Nonce, 1)
	return dst[:len(ciphertext)], nil
}
