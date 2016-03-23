// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The cmac package implements the fast CMac MAC based on
// a block cipher. This mode of operation fixes security
// deficiencies of CBC-MAC (CBC-MAC is secure only for
// fixed-length messages). CMac is equal to OMAC1.
// This implementations supports block ciphers with a
// block size of:
//	- 64 bit (8 byte)
//	- 128 bit (16 byte)
//	- 256 bit (32 byte)
//	- 512 bit (64 byte)
//	- 1024 bit (128 byte)
// Common ciphers like AES, Serpent etc. operate on 128 bit
// blocks. 256, 512 and 1024 are supported for the Threefish
// tweakable block cipher. Ciphers with 64 bit blocks are
// supported, but not recommened.
// CMac (using AES) is specified in RFC 4493.
// See: https://tools.ietf.org/html/rfc4493
package cmac

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"hash"
)

const (
	// minimal irreducible polynomial for blocksize
	p64   = 0x1b    // for 64  bit block ciphers
	p128  = 0x87    // for 128 bit block ciphers (like AES)
	p256  = 0x425   // special for large block ciphers (Threefish)
	p512  = 0x125   // special for large block ciphers (Threefish)
	p1024 = 0x80043 // special for large block ciphers (Threefish)
)

// The CMac struct
type mac struct {
	cipher cipher.Block
	k0, k1 []byte
	buf    []byte
	off    int
}

// Calculates the CMac sum for the message in src using
// the block cipher. If the block cipher is not supported
// by CMac (see package doc), a non-nil error is returned.
// This function returns a MAC with the same length as the
// block size of the cipher.
func Sum(src []byte, c cipher.Block) ([]byte, error) {
	mac, err := New(c)
	if err != nil {
		return nil, err
	}
	mac.Write(src)
	return mac.Sum(nil), nil
}

// Verifies the CMac mac for the message in src using
// the block cipher. If the block cipher is not supported
// by CMac (see package doc), this function returns false.
// This functions returns true if and only if the given mac
// is equal to calculated CMac for src.
func Verify(mac, src []byte, c cipher.Block) bool {
	sum, _ := Sum(src, c)
	return subtle.ConstantTimeCompare(mac, sum) == 1
}

// Creates a new CMac MAC from the given block cipher.
// If the block cipher is not supported by CMac
// (see package doc), a non-nil error is returned.
func New(c cipher.Block) (hash.Hash, error) {
	bs := c.BlockSize()

	var p int
	switch bs {
	default:
		return nil, errors.New("cipher block size not supported")
	case 8:
		p = p64
	case 16:
		p = p128
	case 32:
		p = p256
	case 64:
		p = p512
	case 128:
		p = p1024
	}

	m := &mac{
		cipher: c,
		k0:     make([]byte, bs),
		k1:     make([]byte, bs),
		buf:    make([]byte, bs),
	}
	c.Encrypt(m.k0, m.k0)

	v := shift(m.k0, m.k0)
	m.k0[bs-1] ^= byte(subtle.ConstantTimeSelect(v, p, 0))

	v = shift(m.k1, m.k0)
	m.k1[bs-1] ^= byte(subtle.ConstantTimeSelect(v, p, 0))

	return m, nil
}

// Returns the MAC size of CMac in bytes.
func (h *mac) Size() int { return h.cipher.BlockSize() }

// Returns the block size of CMac in bytes.
func (h *mac) BlockSize() int { return h.cipher.BlockSize() }

// Reset resets the MAC to its initial state.
func (h *mac) Reset() {
	for i := range h.buf {
		h.buf[i] = 0
	}
	h.off = 0
}

// Write adds more data to the running MAC. It never returns an error.
func (h *mac) Write(p []byte) (int, error) {
	bs := len(h.buf)
	left := bs - h.off

	n := len(p)
	if n > left {
		xor(h.buf[h.off:], p[:left])
		p = p[left:]
		h.cipher.Encrypt(h.buf, h.buf)
		h.off = 0
	}

	length := len(p)
	if length > bs {
		nn := length - (length % bs)
		if nn == length {
			nn -= bs
		}
		for i := 0; i < nn; i += bs {
			for j, v := range p[i : i+bs] {
				h.buf[j] ^= v
			}
			h.cipher.Encrypt(h.buf, h.buf)
		}
		p = p[nn:]
	}

	if len(p) > 0 {
		xor(h.buf[h.off:], p)
		h.off += len(p)
	}
	return n, nil
}

// Sum appends the current MAC to b and returns the resulting slice.
// It does not change the underlying MAC state.
func (h *mac) Sum(b []byte) []byte {
	bs := h.cipher.BlockSize()

	// Don't change the buffer so the
	// caller can keep writing and suming.
	hash := make([]byte, bs)

	k := h.k0
	if h.off < bs {
		k = h.k1
	}
	for i, v := range h.buf {
		hash[i] = k[i] ^ v
	}
	if h.off < h.cipher.BlockSize() {
		hash[h.off] ^= 0x80
	}

	h.cipher.Encrypt(hash, hash)
	return append(b, hash...)
}

func xor(dst, src []byte) {
	for i, v := range src {
		dst[i] ^= v
	}
}

func shift(dst, src []byte) int {
	var b, bit byte
	for i := len(src) - 1; i >= 0; i-- { // a range would be nice
		bit = src[i] >> 7
		dst[i] = src[i]<<1 | b
		b = bit
	}
	return int(b)
}
