// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Doc: Look at hc128.go

package hc

import (
	"crypto/cipher"

	"github.com/EncEve/crypto"
)

const mod2048 uint32 = 0x7FF

// A hc256 holds the both states P and Q, the counter,
// 4 byte of the keystream and the offset
type hc256 struct {
	p, q        [1024]uint32
	ctr, stream uint32
	off         uint
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

// key and nonce setup and initialization
func (c *hc256) initialize(key, nonce []byte) {
	w := make([]uint32, 2560)

	// insert the key into the temporally state
	for i, v := range key {
		w[i>>2] |= uint32(v) << uint(8*(i%4))
	}
	// insert the iv into the temporally state
	for i, v := range nonce {
		w[(i>>2)+8] |= uint32(v) << uint(8*(i%4))
	}

	// expand key and nonce with the f1 and f2 functions
	// (2.2 https://eprint.iacr.org/2004/092.pdf)
	var f2, f1 uint32
	for i := 16; i < 2560; i++ {
		f1, f2 = w[i-15], w[i-2]
		f1 = ((f1 >> 7) | (f1 << 25)) ^ ((f1 >> 18) | (f1 << 14)) ^ (f1 >> 3)
		f2 = ((f2 >> 17) | (f2 << 15)) ^ ((f2 >> 19) | (f2 << 13)) ^ (f2 >> 10)
		w[i] = f1 + f2 + w[i-7] + w[i-16] + uint32(i)
	}
	copy(c.p[:], w[512:(512+1024)])
	copy(c.q[:], w[1536:(1536+1024)])

	// do 4096 iterations for initialization
	c.ctr = 0
	for i := 0; i < 4096; i++ {
		c.keystream256()
	}
	c.ctr = 0
}

// The keystream generation function for HC256
// Compare 2.3 at https://eprint.iacr.org/2004/092.pdf
// The functions g1, g2, h1 and h2 are rolled out for optimisation
func (c *hc256) keystream256() uint32 {
	var r, t0, t1, t2, t3 uint32
	j := c.ctr & mod1024

	if c.ctr < 1024 {
		t0 = c.p[(j-3)&mod1024]
		t1 = c.p[(j-1023)&mod1024]
		t2 = t0 ^ t1

		t0 = (t0 >> 10) | (t0 << 22)
		t1 = (t1 >> 23) | (t1 << 9)

		c.p[j] += c.p[(j-10)&mod1024] + (t0 ^ t1) + c.q[t2&mod1024]

		t3 = c.p[(j-12)&mod1024]
		r = c.q[byte(t3)] + c.q[256+((t3>>8)&0xFF)] + c.q[512+((t3>>16)&0xFF)] + c.q[768+((t3>>24)&0xFF)] ^ c.p[j]
	} else {
		t0 = c.q[(j-3)&mod1024]
		t1 = c.q[(j-1023)&mod1024]
		t2 = t0 ^ t1

		t0 = (t0 >> 10) | (t0 << 22)
		t1 = (t1 >> 23) | (t1 << 9)

		c.q[j] += c.q[(j-10)&mod1024] + (t0 ^ t1) + c.p[t2&mod1024]

		t3 = c.q[(j-12)&mod1024]
		r = c.p[byte(t3)] + c.p[256+((t3>>8)&0xFF)] + c.p[512+((t3>>16)&0xFF)] + c.p[768+((t3>>24)&0xFF)] ^ c.q[j]
	}

	c.ctr = (c.ctr + 1) & mod2048
	return r
}
