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

const (
	KeySize   = 16 // The size of the secret key for SipHash.
	BlockSize = 8  // The block size of SipHash.
	Size      = 8  // The size of hash / MAC of SipHash.
)

// The four initialization constants
const (
	c0 = uint64(0x736f6d6570736575)
	c1 = uint64(0x646f72616e646f6d)
	c2 = uint64(0x6c7967656e657261)
	c3 = uint64(0x7465646279746573)
)

// the siphash struct
type siphash struct {
	v0, v1, v2, v3 uint64
	k0, k1         uint64
	buf            [8]byte
	off            int
	ctr            byte
}

func (h *siphash) BlockSize() int { return BlockSize }

func (h *siphash) Size() int { return Size }

func (h *siphash) Reset() {
	h.v0 = h.k0 ^ c0
	h.v1 = h.k1 ^ c1
	h.v2 = h.k0 ^ c2
	h.v3 = h.k1 ^ c3

	h.off = 0
	h.ctr = 0
}

func (h *siphash) Write(src []byte) (int, error) {
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
		blocks(h, in[:nn])
		in = in[nn:]
	}

	if len(in) > 0 {
		h.off = copy(h.buf[:], in)
	}
	return n, nil
}

func (h *siphash) Sum64() uint64 {
	h0 := *h
	for i := h0.off; i < BlockSize-1; i++ {
		h0.buf[i] = 0
	}
	h0.buf[7] = h0.ctr
	return finalize(&h0)
}

func (h *siphash) Sum(b []byte) []byte {
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

// New returns a hash.Hash computing the SipHash checksum.
// The key must be 128 bit (16 byte)
func New(key []byte) (hash.Hash64, error) {
	if k := len(key); k != KeySize {
		return nil, crypto.KeySizeError(k)
	}
	h := new(siphash)
	h.k0 = uint64(key[0]) | uint64(key[1])<<8 | uint64(key[2])<<16 | uint64(key[3])<<24 |
		uint64(key[4])<<32 | uint64(key[5])<<40 | uint64(key[6])<<48 | uint64(key[7])<<56
	h.k1 = uint64(key[8]) | uint64(key[9])<<8 | uint64(key[10])<<16 | uint64(key[11])<<24 |
		uint64(key[12])<<32 | uint64(key[13])<<40 | uint64(key[14])<<48 | uint64(key[15])<<56
	h.Reset()
	return h, nil
}

// Sum computes the SipHash checksum of the msg and
// returns the checksum as a slice.
// The key must be 128 bit (16 byte).
func Sum(msg, key []byte) ([]byte, error) {
	h, err := New(key)
	if err != nil {
		return nil, err
	}
	h.Write(msg)
	return h.Sum(nil), nil
}

// Sum64 computes the SipHash checksum of the msg and
// returns the checksum as a uint64.
// The key must be 128 bit (16 byte).
func Sum64(msg, key []byte) (uint64, error) {
	h, err := New(key)
	if err != nil {
		return 0, err
	}
	h.Write(msg)
	return h.Sum64(), nil
}

// Verify checks whether the given sum is equal to the
// computed checksum of msg. This function returns true
// if and only if the computed checksum is equal to the
// given sum. This function returns false, if the key is
// not 128 bit.
func Verify(sum, msg, key []byte) bool {
	checksum, err := Sum(msg, key)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(sum, checksum) == 1
}
