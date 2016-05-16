// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package hc

const (
	mod512  uint32 = 0x1FF
	mod1024 uint32 = 0x3FF
	mod2048 uint32 = 0x7FF
)

// key and nonce setup and initialization for HC-128
func (c *streamCipher128) initialize(key, nonce []byte) {
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
	for i := range c.p {
		c.p[i] = c.keystream128()
	}
	for i := range c.q {
		c.q[i] = c.keystream128()
	}
	c.ctr = 0
}

// The keystream generation function for HC128
// Compare 2.3 at http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf
// The functions g1, g2, h1 and h2 are rolled out for optimisation
func (c *streamCipher128) keystream128() uint32 {
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

// key and nonce setup and initialization for HC-256
func (c *streamCipher256) initialize(key, nonce []byte) {
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
func (c *streamCipher256) keystream256() uint32 {
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
