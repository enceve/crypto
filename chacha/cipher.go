// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The chacha package implements D J Bernstein's Chacha20 stream cipher algorithm
// and the ChaCha20-Poly1305 AEAD construction described in RFC 7539. Notice that
// this implementation of ChaCha20 can only process 64 x 2^32 bytes (256 GB)
// for one specific key and nonce combination.
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

func chachaCore(dst, src []byte, key *[32]byte, nonce *[12]byte, ctr uint32, rounds int) {
	if len(dst) < len(src) {
		panic("dst buffer is to small")
	}
	var state [16]uint32
	var buf [64]byte

	initialize(key, nonce, &state)
	state[12] = ctr
	length := len(src)
	n := length - (length % 64)
	for i := 0; i < n; i += 64 {
		core(&buf, &state, rounds)
		state[12]++ // inc. counter
		for j, v := range buf {
			dst[i+j] = src[i+j] ^ v
		}
	}
	if n < length {
		core(&buf, &state, rounds)
		for j, v := range buf[:length-n] {
			dst[n+j] = src[n+j] ^ v
		}
	}
}

// XORKeyStream xor`s each byte in the given src with a byte from the
// ChaCha20 key stream. The nonce must be unique for one key for all
// time. If len(dst) < len(src), XORKeyStream panics. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
func XORKeyStream(dst, src []byte, key *[32]byte, nonce *[12]byte, counter uint32) {
	chachaCore(dst, src, key, nonce, counter, 20)
}

// XORKeyStream12 xor`s each byte in the given src with a byte from the
// ChaCha20-12 key stream. The nonce must be unique for one key for all
// time. If len(dst) < len(src), XORKeyStream panics. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
func XORKeyStream12(dst, src []byte, key *[32]byte, nonce *[12]byte, counter uint32) {
	chachaCore(dst, src, key, nonce, counter, 12)
}

// XORKeyStream8 xor`s each byte in the given src with a byte from the
// ChaCha20-8 key stream. The nonce must be unique for one key for all
// time. If len(dst) < len(src), XORKeyStream panics. It is acceptable
// to pass a dst bigger than src, and in that case, XORKeyStream will
// only update dst[:len(src)] and will not touch the rest of dst.
func XORKeyStream8(dst, src []byte, key *[32]byte, nonce *[12]byte, counter uint32) {
	chachaCore(dst, src, key, nonce, counter, 8)
}

// The ChaCha20 stream cipher
type chacha20 struct {
	state  [16]uint32
	stream [64]byte
	off    int
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
	var k [32]byte
	var n [12]byte
	copy(k[:], key)
	copy(n[:], nonce)

	c := &chacha20{}
	initialize(&k, &n, &(c.state))
	return c, nil
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
			src = src[left:]
			dst = dst[left:]
		}
		length -= left
		c.off += left
		if c.off == 64 {
			c.off = 0
		}
	}

	n := length - (length % 64)
	for i := 0; i < n; i += 64 {
		core(&(c.stream), &(c.state), 20)
		c.state[12]++ // inc. counter
		for j := range c.stream {
			dst[i+j] = src[i+j] ^ c.stream[j]
		}
	}
	if n < length {
		core(&(c.stream), &(c.state), 20)
		c.state[12]++ // inc. counter
		for j, v := range c.stream[:length-n] {
			dst[n+j] = src[n+j] ^ v
		}
		c.off += (length - n)
	}
}

// Initialize the cipher with the key and the nonce
func initialize(key *[32]byte, nonce *[12]byte, state *[16]uint32) {
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
