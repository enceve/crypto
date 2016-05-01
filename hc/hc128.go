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
)

// A hc128 holds the both states P and Q, the counter,
// 4 byte of the keystream and the offset
type hc128 struct {
	p, q        [512]uint32
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

// key and nonce setup and initialization
func (c *hc128) initialize(key, nonce []byte) {
	w := make([]uint32, 1280)

	// insert the key into the temporally state
	for i := 0; i < 16; i++ {
		w[i>>2] |= uint32(key[i]) << uint(8*(i%4))
	}
	copy(w[4:8], w[0:4])

	// insert the iv into the temporally state
	for i := 0; i < 16; i++ {
		w[(i>>2)+8] |= uint32(nonce[i]) << uint(8*(i%4))
	}
	copy(w[12:16], w[8:12])

	// expand key and nonce with the f1 and f2 functions
	// (2.2 http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf)
	var f2, f1 uint32
	for i := 16; i < 1280; i++ {
		f1, f2 = w[i-15], w[i-2]
		f1 = ((f1 >> 7) | (f1 << 25)) ^ ((f1 >> 18) | (f1 << 14)) ^ (f1 >> 3)
		f2 = ((f2 >> 17) | (f2 << 15)) ^ ((f2 >> 19) | (f2 << 13)) ^ (f2 >> 10)
		w[i] = f1 + f2 + w[i-7] + w[i-16] + uint32(i)
	}
	copy(c.p[:], w[256:(256+512)])
	copy(c.q[:], w[768:(768+512)])

	// do 1024 iterations for initialization
	c.ctr = 0
	for i, _ := range c.p {
		c.p[i] = c.keystream128()
	}
	for i, _ := range c.q {
		c.q[i] = c.keystream128()
	}
	c.ctr = 0
}

// The keystream generation function for HC128
// Compare 2.3 at http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
// The functions g1, g2, h1 and h2 are rolled out for optimisation
func (c *hc128) keystream128() uint32 {
	var r, t0, t1, t2, t3 uint32
	j := c.ctr & mod512

	if c.ctr < 512 {
		t0 = c.p[(j-3)&mod512]
		t1 = c.p[(j-10)&mod512]
		t2 = c.p[(j-511)&mod512]
		t3 = c.p[(j-12)&mod512]
		t0 = ((t0 >> 10) | (t0 << 22))
		t1 = ((t1 >> 8) | (t1 << 24))
		t2 = ((t2 >> 23) | (t2 << 9))
		c.p[j] += (t0 ^ t2) + t1
		r = (c.q[t3&0xFF] + c.q[256+((t3>>16)&0xFF)]) ^ c.p[j]
	} else {
		t0 = c.q[(j-3)&mod512]
		t1 = c.q[(j-10)&mod512]
		t2 = c.q[(j-511)&mod512]
		t3 = c.q[(j-12)&mod512]
		t0 = ((t0 << 10) | (t0 >> 22))
		t1 = ((t1 << 8) | (t1 >> 24))
		t2 = ((t2 << 23) | (t2 >> 9))
		c.q[j] += (t0 ^ t2) + t1
		r = c.p[t3&0xFF] + c.p[256+((t3>>16)&0xFF)] ^ c.q[j]
	}

	c.ctr = (c.ctr + 1) & mod1024
	return r
}
