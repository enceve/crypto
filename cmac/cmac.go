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

	"github.com/enceve/crypto"
)

const (
	// minimal irreducible polynomial for blocksize
	p64   = 0x1b    // for 64  bit block ciphers
	p128  = 0x87    // for 128 bit block ciphers (like AES)
	p256  = 0x425   // special for large block ciphers (Threefish)
	p512  = 0x125   // special for large block ciphers (Threefish)
	p1024 = 0x80043 // special for large block ciphers (Threefish)
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

func (h *macFunc) Write(msg []byte) (int, error) {
	bs := h.BlockSize()
	n := len(msg)

	if h.off > 0 {
		dif := bs - h.off
		if n > dif {
			crypto.XOR(h.buf[h.off:], h.buf[h.off:], msg[:dif])
			msg = msg[dif:]
			h.cipher.Encrypt(h.buf, h.buf)
			h.off = 0
		} else {
			crypto.XOR(h.buf[h.off:], h.buf[h.off:], msg)
			h.off += n
			return n, nil
		}
	}

	if length := len(msg); length > bs {
		nn := length & (^(bs - 1))
		if length == nn {
			nn -= bs
		}
		for i := 0; i < nn; i += bs {
			crypto.XOR(h.buf, h.buf, msg[i:i+bs])
			h.cipher.Encrypt(h.buf, h.buf)
		}
		msg = msg[nn:]
	}

	if length := len(msg); length > 0 {
		crypto.XOR(h.buf[h.off:], h.buf[h.off:], msg)
		h.off += length
	}

	return n, nil
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
	crypto.XOR(hash, k, h.buf)
	if h.off < h.cipher.BlockSize() {
		hash[h.off] ^= 0x80
	}

	h.cipher.Encrypt(hash, hash)
	return append(b, hash...)
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
