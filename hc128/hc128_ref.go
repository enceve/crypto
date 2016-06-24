// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package hc128

import "github.com/enceve/crypto"

func (c *streamCipher) XORKeyStream(dst, src []byte) {
	length := len(src)
	if len(dst) < length {
		panic("dst buffer is to small")
	}

	if c.off > 0 {
		left := 4 - c.off
		if left > length {
			left = length
		}
		for i, v := range c.keyStream[c.off : c.off+left] {
			dst[i] = src[i] ^ v
		}
		src = src[left:]
		dst = dst[left:]
		length -= left
		c.off += left
		if c.off == 4 {
			c.off = 0
		}
	}

	n := length - (length % 4)
	for i := 0; i < n; i += 4 {
		k := genKeyStream(&(c.ctr), &(c.p), &(c.q))
		dst[i] = src[i] ^ byte(k)
		dst[i+1] = src[i+1] ^ byte(k>>8)
		dst[i+2] = src[i+2] ^ byte(k>>16)
		dst[i+3] = src[i+3] ^ byte(k>>24)
	}

	length -= n
	if length > 0 {
		k := genKeyStream(&(c.ctr), &(c.p), &(c.q))
		c.keyStream[0] = byte(k)
		c.keyStream[1] = byte(k >> 8)
		c.keyStream[2] = byte(k >> 16)
		c.keyStream[3] = byte(k >> 24)
		c.off += crypto.XOR(dst[n:], src[n:], c.keyStream[:])
	}
}
