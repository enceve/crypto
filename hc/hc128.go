package hc

// key & iv setup and initialization
func (c *hc128) initialize(key, iv []byte) {
	w := make([]uint32, 1280)

	// insert the key into the temporally state
	for i := 0; i < 16; i++ {
		w[i>>2] |= uint32(key[i]) << uint(8*(i%4))
	}
	copy(w[4:8], w[0:4])

	// insert the iv into the temporally state
	for i := 0; i < 16; i++ {
		w[(i>>2)+8] |= uint32(iv[i]) << uint(8*(i%4))
	}
	copy(w[12:16], w[8:12])

	// expand key and iv with the f1 and f2 functions
	// (2.2 http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf)
	var f2, f1 uint32
	for i := 16; i < 1280; i++ {
		f1, f2 = w[i-15], w[i-2]
		f1 = ((f1 >> 7) | (f1 << 25)) ^ ((f1 >> 18) | (f1 << 14)) ^ (f1 >> 3)
		f2 = ((f2 >> 17) | (f2 << 15)) ^ ((f2 >> 19) | (f2 << 13)) ^ (f2 >> 10)
		w[i] = f1 + f2 + w[i-7] + w[i-16] + uint32(i)
	}
	copy(c.p, w[256:(256+512)])
	copy(c.q, w[768:(768+512)])

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

func (c *hc128) XORKeyStream(dst, src []byte) {
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
		k := c.keystream128()
		dst[dOff] = src[sOff] ^ byte(k)
		dst[dOff+1] = src[sOff+1] ^ byte(k>>8)
		dst[dOff+2] = src[sOff+2] ^ byte(k>>16)
		dst[dOff+3] = src[sOff+3] ^ byte(k>>24)

		dOff, sOff = dOff+4, sOff+4
		n -= 4
	}
	if n > 0 {
		c.stream = c.keystream128()
		c.off = 0
		for n > 0 && c.off < 4 {
			dst[dOff] = src[sOff] ^ byte(c.stream>>(c.off*8))
			dOff, sOff, c.off = dOff+1, sOff+1, c.off+1
			n--
		}
	}
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
