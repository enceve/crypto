// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package chacha

import (
	"unsafe"

	"github.com/enceve/crypto"
)

// XORKeyStream crypts bytes from src to dst using the given key, nonce and counter.
// The rounds argument specifies the number of rounds performed for keystream generation.
// (Common values are 20, 12 or 8) Src and dst may be the same slice but otherwise should
// not overlap. If len(dst) < len(src) the behavior is undefined.
func XORKeyStream(dst, src []byte, nonce *[12]byte, key *[32]byte, counter uint32, rounds int) {
	var state [16]uint32

	state[0] = constants[0]
	state[1] = constants[1]
	state[2] = constants[2]
	state[3] = constants[3]

	keyPtr := (*[8]uint32)(unsafe.Pointer(&key[0]))
	state[4] = keyPtr[0]
	state[5] = keyPtr[1]
	state[6] = keyPtr[2]
	state[7] = keyPtr[3]
	state[8] = keyPtr[4]
	state[9] = keyPtr[5]
	state[10] = keyPtr[6]
	state[11] = keyPtr[7]

	state[12] = counter

	noncePtr := (*[3]uint32)(unsafe.Pointer(&nonce[0]))
	state[13] = noncePtr[0]
	state[14] = noncePtr[1]
	state[15] = noncePtr[2]

	length := len(src)
	n := length & (^(64 - 1))
	if n > 0 {
		XORBlocks(dst, src, &state, rounds)
	}

	length -= n
	if length > 0 {
		var block [64]byte
		Core(&block, &state, rounds)

		crypto.XOR(dst[n:], src[n:], block[:])
	}
}

// NewCipher returns a new *chacha.Cipher implementing the ChaCha/X (X = rounds)
// stream cipher. The nonce must be unique for one
// key for all time.
func NewCipher(nonce *[12]byte, key *[32]byte, rounds int) *Cipher {
	if rounds%2 != 0 {
		panic("rounds must be a multiply of 2")
	}
	c := new(Cipher)
	c.rounds = rounds

	c.state[0] = constants[0]
	c.state[1] = constants[1]
	c.state[2] = constants[2]
	c.state[3] = constants[3]

	keyPtr := (*[8]uint32)(unsafe.Pointer(&key[0]))
	c.state[4] = keyPtr[0]
	c.state[5] = keyPtr[1]
	c.state[6] = keyPtr[2]
	c.state[7] = keyPtr[3]
	c.state[8] = keyPtr[4]
	c.state[9] = keyPtr[5]
	c.state[10] = keyPtr[6]
	c.state[11] = keyPtr[7]

	c.state[12] = 0

	noncePtr := (*[3]uint32)(unsafe.Pointer(&nonce[0]))
	c.state[13] = noncePtr[0]
	c.state[14] = noncePtr[1]
	c.state[15] = noncePtr[2]

	return c
}

// XORKeyStream crypts bytes from src to dst. Src and dst may be the same slice
// but otherwise should not overlap. If len(dst) < len(src) the function panics.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	length := len(src)
	if len(dst) < length {
		panic("dst buffer is to small")
	}

	if c.off > 0 {
		left := 64 - c.off
		if left > length {
			left = length
		}
		for i, v := range c.block[c.off : c.off+left] {
			dst[i] = src[i] ^ v
		}
		src = src[left:]
		dst = dst[left:]
		length -= left
		c.off += left
		if c.off == 64 {
			c.off = 0
		}
	}

	n := length & (^(64 - 1))
	if n > 0 {
		XORBlocks(dst, src, &(c.state), c.rounds)
	}

	length -= n
	if length > 0 {
		Core(&(c.block), &(c.state), c.rounds)
		c.state[12]++

		c.off += crypto.XOR(dst[n:], src[n:], c.block[:])
	}
}

// xorBlocksSSE64 crypts one 64 byte chunk from src to dst using SSE2 SIMD.
func xorBlocksSSE64(dst *byte, src *byte, state *[16]uint32, rounds int)

// xorBlocksSSE128 crypts one 128 byte chunk from src to dst using SSE2 SIMD.
func xorBlocksSSE128(dst *byte, src *byte, state *[16]uint32, rounds int)

// xorBlocksSSE256 crypts as many as possible 256 byte chunks (length argument)
// from src to dst using SSE2 SIMD.
func xorBlocksSSE256(dst *byte, src *byte, length uint64, state *[16]uint32, rounds int)

// XORBlocks crypts full block ( len(src) - (len(src) mod 64) bytes ) from src to
// dst using the state. Src and dst may be the same slice
// but otherwise should not overlap. If len(dst) < len(src) the behavior is undefined.
// This function increments the counter.
func XORBlocks(dst, src []byte, state *[16]uint32, rounds int) {
	length := len(src)
	n := length & (^(256 - 1))
	if n > 0 {
		xorBlocksSSE256(&dst[0], &src[0], uint64(n), state, rounds)
	}

	if length-n >= 128 {
		xorBlocksSSE128(&dst[n], &src[n], state, rounds)
		n += 128
	}

	if length-n >= 64 {
		xorBlocksSSE64(&dst[n], &src[n], state, rounds)
	}
}

// Core generates 64 byte keystream from the given state performing 'rounds' rounds
// and writes them to dst. This function expects valid values. (no nil ptr etc.)
// Core does NOT increment the counter.
func Core(dst *[64]byte, state *[16]uint32, rounds int)
