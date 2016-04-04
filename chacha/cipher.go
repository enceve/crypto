// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The chacha package implements D J Bernstein's Chacha20 stream cipher algorithm.
// See: http://cr.yp.to/chacha/chacha-20080128.pdf
// There are two variants of this cipher:
//		- the original by Bernstein
// 		- the version described in RFC 7539.
// This package implements the version described in RFC 7539.
// Furthermore the AEAD cipher ChaCha20-Poly1305 (RFC 7539) is implemented here.
// Notice, that this implementation of ChaCha20 can only process 64 x 2^32 bytes
// for one specific key and nonce combination. So the amount of data, en / decrypted by one
// key-nonce combination, is limited by 256 GB.
package chacha

import (
	"crypto/cipher"

	"github.com/EncEve/crypto"
)

const NonceSize = 12 // The size of the nonce for ChaCha20 in bytes

// The four RFC 7539 constants
const (
	const0 = 0x61707865
	const1 = 0x3320646e
	const2 = 0x79622d32
	const3 = 0x6b206574
)

type chacha20 struct {
	state  [16]uint32
	stream [64]byte
	off    uint
}

// XORKeyStream xor`s each byte in the given src with a byte from the
// ChaCha20 key stream. The key must be 256 bit (32 byte), otherwise this
// function panics. The nonce must be 96 bit (12 byte) and unique for one
// key for all time. If the nonce is not 96 bit long, this function panics.
// The ctr argument sets the counter for the ChaCha20 key stream generation.
// If len(dst) < len(src), XORKeyStream panics. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
func XORKeyStream(dst, key, nonce []byte, ctr uint32, src []byte) {
	if k := len(key); k != 32 {
		panic(crypto.KeySizeError(k))
	}
	if n := len(nonce); n != NonceSize {
		panic(crypto.NonceSizeError(n))
	}
	c := &chacha20{
		off: 64,
	}
	initialize(key, nonce, &(c.state))
	c.state[12] = ctr
	c.XORKeyStream(dst, src)
}

// New returns a new cipher.Stream implementing the ChaCha20
// cipher. The key must be exactly 256 bit (32 byte). The
// nonce must be exactly 96 bit (12 byte) and unique for one
// key for all time.
func New(key, nonce []byte) (cipher.Stream, error) {
	if k := len(key); k != 32 {
		return nil, crypto.KeySizeError(k)
	}
	if n := len(nonce); n != NonceSize {
		return nil, crypto.NonceSizeError(n)
	}
	c := &chacha20{
		off: 64,
	}
	initialize(key, nonce, &(c.state))
	return c, nil
}

func (c *chacha20) XORKeyStream(dst, src []byte) {
	n := len(src)
	if len(dst) < n {
		panic("dst buffer to small")
	}
	dOff, sOff := 0, 0
	if c.off < 64 {
		for n > 0 && c.off < 64 {
			dst[dOff] = src[sOff] ^ c.stream[c.off]
			dOff, sOff, c.off = dOff+1, sOff+1, c.off+1
			n--
		}
	}
	for n >= 64 {
		core(&(c.stream), &(c.state))
		c.state[12]++ // inc. counter
		for i := range c.stream {
			dst[dOff+i] = src[sOff+i] ^ c.stream[i]
		}
		dOff += 64
		sOff += 64
		n -= 64
	}
	if n > 0 {
		c.off = 0
		core(&(c.stream), &(c.state))
		c.state[12]++ // inc. counter
		for i := 0; n > 0; i++ {
			dst[dOff+i] = src[sOff+i] ^ c.stream[i]
			c.off++
			n--
		}
	}
}

// Initialize the cipher with the key and the nonce
func initialize(key, nonce []byte, state *[16]uint32) {
	// The four rfc constants
	state[0] = const0
	state[1] = const1
	state[2] = const2
	state[3] = const3

	// The 256 bit key
	state[4] = uint32(key[0]) | uint32(key[1])<<8 | uint32(key[2])<<16 | uint32(key[3])<<24
	state[5] = uint32(key[4]) | uint32(key[5])<<8 | uint32(key[6])<<16 | uint32(key[7])<<24
	state[6] = uint32(key[8]) | uint32(key[9])<<8 | uint32(key[10])<<16 | uint32(key[11])<<24
	state[7] = uint32(key[12]) | uint32(key[13])<<8 | uint32(key[14])<<16 | uint32(key[15])<<24
	state[8] = uint32(key[16]) | uint32(key[17])<<8 | uint32(key[18])<<16 | uint32(key[19])<<24
	state[9] = uint32(key[20]) | uint32(key[21])<<8 | uint32(key[22])<<16 | uint32(key[23])<<24
	state[10] = uint32(key[24]) | uint32(key[25])<<8 | uint32(key[26])<<16 | uint32(key[27])<<24
	state[11] = uint32(key[28]) | uint32(key[29])<<8 | uint32(key[30])<<16 | uint32(key[31])<<24

	// The counter
	state[12] = 0

	// The 96 bit nonce
	state[13] = uint32(nonce[0]) | uint32(nonce[1])<<8 | uint32(nonce[2])<<16 | uint32(nonce[3])<<24
	state[14] = uint32(nonce[4]) | uint32(nonce[5])<<8 | uint32(nonce[6])<<16 | uint32(nonce[7])<<24
	state[15] = uint32(nonce[8]) | uint32(nonce[9])<<8 | uint32(nonce[10])<<16 | uint32(nonce[11])<<24
}
