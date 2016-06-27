// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package siphash implements a hash / MAC function
// developed Jean-Philippe Aumasson and Daniel J Bernstein
// in 2012. SipHash computes 64-bit message authentication
// code from a variable-length message and a 128-bit secret
// key. It was designed to be efficient even for short inputs,
// with performance comparable to non-cryptographic hash
// functions. This package implements SipHash with the
// recommended parameters: c = 2 and d = 4.
package siphash

import "crypto/subtle"

// The size of the SipHash authentication tag in bytes.
const TagSize = 8

// The four initialization constants
const (
	c0 = uint64(0x736f6d6570736575)
	c1 = uint64(0x646f72616e646f6d)
	c2 = uint64(0x6c7967656e657261)
	c3 = uint64(0x7465646279746573)
)

// Verify checks whether the given sum is equal to the
// computed checksum of msg. This function returns true
// if and only if the computed checksum is equal to the
// given sum.
func Verify(sum *[TagSize]byte, msg []byte, key *[16]byte) bool {
	var out [TagSize]byte
	Sum(&out, msg, key)
	return subtle.ConstantTimeCompare(sum[:], out[:]) == 1
}

// The siphash hash struct implementing hash.Hash
type hashFunc struct {
	hVal  [4]uint64
	key   [2]uint64
	block [TagSize]byte
	off   int
	ctr   byte
}

func (h *hashFunc) BlockSize() int { return TagSize }

func (h *hashFunc) Size() int { return TagSize }

func (h *hashFunc) Reset() {
	h.hVal[0] = h.key[0] ^ c0
	h.hVal[1] = h.key[1] ^ c1
	h.hVal[2] = h.key[0] ^ c2
	h.hVal[3] = h.key[1] ^ c3

	h.off = 0
	h.ctr = 0
}

func (h *hashFunc) Write(p []byte) (int, error) {
	n := len(p)
	h.ctr += byte(n)

	if h.off > 0 {
		dif := TagSize - h.off
		if n > dif {
			h.off += copy(h.block[h.off:], p[:dif])
			p = p[dif:]
			core(&(h.hVal), h.block[:])
			h.off = 0
		} else {
			h.off += copy(h.block[h.off:], p)
			return n, nil
		}
	}

	if nn := len(p); nn >= TagSize {
		nn &= (^(TagSize - 1))
		core(&(h.hVal), p[:nn])
		p = p[nn:]
	}

	if len(p) > 0 {
		h.off = copy(h.block[:], p)
	}
	return n, nil
}

func (h *hashFunc) Sum64() uint64 {
	hVal := h.hVal
	block := h.block
	for i := h.off; i < TagSize-1; i++ {
		block[i] = 0
	}
	block[7] = h.ctr
	return finalize(&hVal, &block)
}

func (h *hashFunc) Sum(b []byte) []byte {
	r := h.Sum64()

	var out [TagSize]byte
	out[0] = byte(r)
	out[1] = byte(r >> 8)
	out[2] = byte(r >> 16)
	out[3] = byte(r >> 24)
	out[4] = byte(r >> 32)
	out[5] = byte(r >> 40)
	out[6] = byte(r >> 48)
	out[7] = byte(r >> 56)
	return append(b, out[:]...)
}
