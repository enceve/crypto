// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The package siphash implements a hash / MAC function
// developed Jean-Philippe Aumasson and Daniel J Bernstein
// in 2012. SipHash computes 64-bit message authentication
// code from a variable-length message and a 128-bit secret
// key. It was designed to be efficient even for short inputs,
// with performance comparable to non-cryptographic hash
// functions. This package implements SipHash with the
// recommended parameters: c = 2 and d = 4.
package siphash

import (
	"crypto/subtle"
	"hash"

	"github.com/EncEve/crypto"
)

// The four initialization constants
const (
	c0 = uint64(0x736f6d6570736575)
	c1 = uint64(0x646f72616e646f6d)
	c2 = uint64(0x6c7967656e657261)
	c3 = uint64(0x7465646279746573)
)

const (
	BlockSize = 8 // The block size of SipHash in bytes.
	Size      = 8 // The size of hash / MAC in bytes.
)

// New returns a hash.Hash64 computing the SipHash checksum.
// The key must be 128 bit (16 byte).
func New(key []byte) (hash.Hash64, error) {
	if k := len(key); k != 16 {
		return nil, crypto.KeySizeError(k)
	}
	h := new(hashFunc)
	h.k0 = uint64(key[0]) | uint64(key[1])<<8 | uint64(key[2])<<16 | uint64(key[3])<<24 |
		uint64(key[4])<<32 | uint64(key[5])<<40 | uint64(key[6])<<48 | uint64(key[7])<<56
	h.k1 = uint64(key[8]) | uint64(key[9])<<8 | uint64(key[10])<<16 | uint64(key[11])<<24 |
		uint64(key[12])<<32 | uint64(key[13])<<40 | uint64(key[14])<<48 | uint64(key[15])<<56
	h.Reset()
	return h, nil
}

// Sum generates an authenticator for msg using a 128 bit (16 byte) key
// and puts the 8-byte result into out.
func Sum(out *[Size]byte, msg []byte, key *[16]byte) {
	r := Sum64(msg, key)

	out[0] = byte(r)
	out[1] = byte(r >> 8)
	out[2] = byte(r >> 16)
	out[3] = byte(r >> 24)
	out[4] = byte(r >> 32)
	out[5] = byte(r >> 40)
	out[6] = byte(r >> 48)
	out[7] = byte(r >> 56)
}

// Sum generates and returns the 64 bit authenticator
// for msg using a 128 bit (16 byte) key
func Sum64(msg []byte, key *[16]byte) uint64 {
	h := new(hashFunc)
	h.k0 = uint64(key[0]) | uint64(key[1])<<8 | uint64(key[2])<<16 | uint64(key[3])<<24 |
		uint64(key[4])<<32 | uint64(key[5])<<40 | uint64(key[6])<<48 | uint64(key[7])<<56
	h.k1 = uint64(key[8]) | uint64(key[9])<<8 | uint64(key[10])<<16 | uint64(key[11])<<24 |
		uint64(key[12])<<32 | uint64(key[13])<<40 | uint64(key[14])<<48 | uint64(key[15])<<56
	h.Reset()

	h.Write(msg)

	return h.Sum64()
}

// Verify checks whether the given sum is equal to the
// computed checksum of msg. This function returns true
// if and only if the computed checksum is equal to the
// given sum.
func Verify(sum *[Size]byte, msg []byte, key *[16]byte) bool {
	var out [Size]byte
	Sum(&out, msg, key)
	return subtle.ConstantTimeCompare(sum[:], out[:]) == 1
}

// The siphash hash struct implementing hash.Hash
type hashFunc struct {
	v0, v1, v2, v3 uint64
	k0, k1         uint64
	buf            [Size]byte
	off            int
	ctr            byte
}

func (h *hashFunc) BlockSize() int { return BlockSize }

func (h *hashFunc) Size() int { return Size }

func (h *hashFunc) Reset() {
	h.v0 = h.k0 ^ c0
	h.v1 = h.k1 ^ c1
	h.v2 = h.k0 ^ c2
	h.v3 = h.k1 ^ c3

	h.off = 0
	h.ctr = 0
}

func (h *hashFunc) Write(src []byte) (int, error) {
	in := src
	n := len(in)
	h.ctr += uint8(n)
	if h.off > 0 {
		var f int
		if n > BlockSize-h.off {
			f = copy(h.buf[h.off:], in[:(BlockSize-h.off)])
		} else {
			f = copy(h.buf[h.off:], in[:n])
		}
		h.off += f
		if h.off == BlockSize {
			flush(h)
			h.off = 0
		}
		in = in[f:]
	}

	nn := len(in)
	if nn >= BlockSize {
		nn = nn - (nn % BlockSize)
		siphashCore(h, in[:nn])
		in = in[nn:]
	}

	if len(in) > 0 {
		h.off = copy(h.buf[:], in)
	}
	return n, nil
}

func (h *hashFunc) Sum64() uint64 {
	h0 := *h
	for i := h0.off; i < BlockSize-1; i++ {
		h0.buf[i] = 0
	}
	h0.buf[7] = h0.ctr
	return siphashFinalize(&h0)
}

func (h *hashFunc) Sum(b []byte) []byte {
	r := h.Sum64()

	var out [Size]byte
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
