// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The hc package implements the both stream ciphers
// HC-128 and HC-256 from the eSTREAM portfolio (software).
// Both ciphers were designed by Hongjun Wu.
// HC-128 and HC-256 are fast stream ciphers after[!]
// initialization. This may not be an issue, but if keys
// change too often, both ciphers spend a lot of time in
// initialization. In this case another cipher may perform
// better.
package hc

import (
	"crypto/cipher"

	"github.com/EncEve/crypto"
)

const (
	mod512  uint32 = 0x1FF
	mod1024 uint32 = 0x3FF
	mod2048 uint32 = 0x7FF
)

// A hc128 holds the both states P and Q, the counter,
// 4 byte of the keystream and the offset
type hc128 struct {
	p, q        [512]uint32
	ctr, stream uint32
	off         uint
}

// A hc256 holds the both states P and Q, the counter,
// 4 byte of the keystream and the offset
type hc256 struct {
	p, q        [1024]uint32
	ctr, stream uint32
	off         uint
}

// New128 returns a new cipher.Stream implementing the
// HC-128 cipher. The key and nonce argument must be
// 128 bit (16 byte).
func New128(key, nonce []byte) (cipher.Stream, error) {
	if k := len(key); k != 16 {
		return nil, crypto.KeySizeError(k)
	}
	if n := len(nonce); n != 16 {
		return nil, crypto.NonceSizeError(n)
	}
	c := &hc128{
		off:    4,
		ctr:    0,
		stream: 0,
	}
	c.initialize(key, nonce)

	return c, nil
}

func (c *hc128) XORKeyStream(dst, src []byte) {
	length := len(src)
	if len(dst) < length {
		panic("dst buffer to small")
	}
	if c.off > 0 {
		left := int(4 - c.off)
		if left > length {
			left = length
		}
		for i := 0; i < left; i++ {
			dst[i] = src[i] ^ byte(c.stream>>(c.off*8))
			c.off++
		}
		src = src[left:]
		dst = dst[left:]
		length -= left
		c.off += uint(left)
		if c.off == 4 {
			c.off = 0
		}
	}
	var ks uint32
	n := length - (length % 4)
	for i := 0; i < n; i += 4 {
		ks = c.keystream128()
		dst[i] = src[i] ^ byte(ks)
		dst[i+1] = src[i+1] ^ byte(ks>>8)
		dst[i+2] = src[i+2] ^ byte(ks>>16)
		dst[i+3] = src[i+3] ^ byte(ks>>24)
	}
	if n < length {
		c.stream = c.keystream128()
		for i := (length - n); i < length; i++ {
			dst[i] = src[i] ^ byte(c.stream>>(c.off*8))
			c.off++
		}
	}
}

// New256 returns a new cipher.Stream implementing the
// HC-256 cipher. The key and nonce argument must be
// 256 bit (32 byte).
func New256(key, nonce []byte) (cipher.Stream, error) {
	if k := len(key); k != 32 {
		return nil, crypto.KeySizeError(k)
	}
	if n := len(nonce); n != 32 {
		return nil, crypto.NonceSizeError(n)
	}
	c := &hc256{
		off:    4,
		ctr:    0,
		stream: 0,
	}
	c.initialize(key, nonce)

	return c, nil
}

func (c *hc256) XORKeyStream(dst, src []byte) {
	length := len(src)
	if len(dst) < length {
		panic("dst buffer to small")
	}
	if c.off > 0 {
		left := int(4 - c.off)
		if left > length {
			left = length
		}
		for i := 0; i < left; i++ {
			dst[i] = src[i] ^ byte(c.stream>>(c.off*8))
			c.off++
		}
		src = src[left:]
		dst = dst[left:]
		length -= left
		c.off += uint(left)
		if c.off == 4 {
			c.off = 0
		}
	}
	var ks uint32
	n := length - (length % 4)
	for i := 0; i < n; i += 4 {
		ks = c.keystream256()
		dst[i] = src[i] ^ byte(ks)
		dst[i+1] = src[i+1] ^ byte(ks>>8)
		dst[i+2] = src[i+2] ^ byte(ks>>16)
		dst[i+3] = src[i+3] ^ byte(ks>>24)
	}
	if n < length {
		c.stream = c.keystream256()
		for i := (length - n); i < length; i++ {
			dst[i] = src[i] ^ byte(c.stream>>(c.off*8))
			c.off++
		}
	}
}
