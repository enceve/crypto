package hc

// key & iv setup and initialization
func (c *hc256) initialize(key, iv []byte) {
	w := make([]uint32, 2560)

	// insert the key into the temporally state
	for i, v := range key {
		w[i>>2] |= uint32(v) << uint(8*(i%4))
	}
	// insert the iv into the temporally state
	for i, v := range iv {
		w[(i>>2)+8] |= uint32(v) << uint(8*(i%4))
	}

	// expand key and iv with the f1 and f2 functions
	// (2.2 https://eprint.iacr.org/2004/092.pdf)
	var f2, f1 uint32
	for i := 16; i < 2560; i++ {
		f1, f2 = w[i-15], w[i-2]
		f1 = ((f1 >> 7) | (f1 << 25)) ^ ((f1 >> 18) | (f1 << 14)) ^ (f1 >> 3)
		f2 = ((f2 >> 17) | (f2 << 15)) ^ ((f2 >> 19) | (f2 << 13)) ^ (f2 >> 10)
		w[i] = f1 + f2 + w[i-7] + w[i-16] + uint32(i)
	}
	copy(c.p, w[512:(512+1024)])
	copy(c.q, w[1536:(1536+1024)])

	// do 4096 iterations for initialization
	c.ctr = 0
	for i := 0; i < 4096; i++ {
		c.keystream256()
	}
	c.ctr = 0
}

func (c *hc256) XORKeyStream(dst, src []byte) {
	n := len(src)
	if len(dst) < n {
		panic("hc: output buffer to small")
	}
	dOff, sOff := 0, 0
	for n > 0 && c.off < 4 {
		dst[dOff] = src[sOff] ^ byte(c.stream>>(c.off*8))
		dOff, sOff, c.off = dOff+1, sOff+1, c.off+1
		n--
	}
	for n >= 4 {
		k := c.keystream256()
		dst[dOff] = src[sOff] ^ byte(k)
		dst[dOff+1] = src[sOff+1] ^ byte(k>>8)
		dst[dOff+2] = src[sOff+2] ^ byte(k>>16)
		dst[dOff+3] = src[sOff+3] ^ byte(k>>24)

		dOff, sOff = dOff+4, sOff+4
		n -= 4
	}
	if n > 0 {
		c.stream = c.keystream256()
		c.off = 0
		for n > 0 && c.off < 4 {
			dst[dOff] = src[sOff] ^ byte(c.stream>>(c.off*8))
			dOff, sOff, c.off = dOff+1, sOff+1, c.off+1
			n--
		}
	}
}

// The keystream generation function for HC128
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
