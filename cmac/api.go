// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package cmac implements the fast CMac MAC based on
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
package cmac

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"hash"
)

// Sum computes the CMac checksum of msg using the cipher.Block.
// If the block cipher is not supported  by CMac (see package doc),
// a non-nil error is returned.
func Sum(msg []byte, c cipher.Block) ([]byte, error) {
	mac, err := New(c)
	if err != nil {
		return nil, err
	}
	mac.Write(msg)
	return mac.Sum(nil), nil
}

// Verify computes the CMac checksum of msg and compares it with the
// given mac. This functions returns true if and only if the given mac
// is equal to computed one. If the block cipher is not supported
// by CMac (see package doc), this function returns false.
func Verify(mac, msg []byte, c cipher.Block) bool {
	sum, err := Sum(msg, c)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(mac, sum) == 1
}

// New returns a hash.Hash computing the CMac checksum.
// If the block cipher is not supported by CMac
// (see package doc), a non-nil error is returned.
func New(c cipher.Block) (hash.Hash, error) {
	if c == nil {
		return nil, errors.New("the cipher.Block must not be nil")
	}
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

	m := &macFunc{
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

// The CMac message auth. function
type macFunc struct {
	cipher cipher.Block
	k0, k1 []byte
	buf    []byte
	off    int
}

func (h *macFunc) Size() int { return h.cipher.BlockSize() }

func (h *macFunc) BlockSize() int { return h.cipher.BlockSize() }

func (h *macFunc) Reset() {
	for i := range h.buf {
		h.buf[i] = 0
	}
	h.off = 0
}

func (h *macFunc) Write(p []byte) (int, error) {
	bs := len(h.buf)
	length := len(p)

	// fill and process buffer (if neccessary)
	if left := bs - h.off; len(p) > left {
		xor(h.buf[h.off:], p[:left])
		p = p[left:]
		length -= left
		h.cipher.Encrypt(h.buf, h.buf)
		h.off = 0
	}

	// proccess complete blocks accept for the last
	if length > bs {
		n := length & (^(bs - 1))
		if n == length {
			n -= bs
		}
		for i := 0; i < n; i += bs {
			for j, v := range p[i : i+bs] {
				h.buf[j] ^= v
			}
			h.cipher.Encrypt(h.buf, h.buf)
		}
		p = p[n:]
	}

	// proccess the last (may incomplete block)
	if n := len(p); n > 0 {
		xor(h.buf[h.off:], p)
		h.off += n
	}
	return length, nil
}

func (h *macFunc) Sum(b []byte) []byte {
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
