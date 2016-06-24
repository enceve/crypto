// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package hc256 implements the stream cipher
// HC-256  designed by Hongjun Wu.
package hc256 // import "github.com/enceve/crypto/hc256"

import "crypto/cipher"

const (
	mod1024 uint32 = 0x3FF
	mod2048 uint32 = 0x7FF
)

// NewCipher returns a new cipher.Stream implementing the
// HC-256 cipher with the given key and nonce.
func NewCipher(nonce, key *[32]byte) cipher.Stream {
	c := new(streamCipher)
	initialize(nonce, key, &(c.p), &(c.q))
	return c
}

type streamCipher struct {
	p, q      [1024]uint32
	ctr       uint32
	keyStream [4]byte
	off       int
}

func initialize(nonce, key *[32]byte, p, q *[1024]uint32) {
	var tmp [2560]uint32

	tmp[0] = uint32(key[0]) | (uint32(key[1]) << 8) | (uint32(key[2]) << 16) | (uint32(key[3]) << 24)
	tmp[1] = uint32(key[4]) | (uint32(key[5]) << 8) | (uint32(key[6]) << 16) | (uint32(key[7]) << 24)
	tmp[2] = uint32(key[8]) | (uint32(key[9]) << 8) | (uint32(key[10]) << 16) | (uint32(key[11]) << 24)
	tmp[3] = uint32(key[12]) | (uint32(key[13]) << 8) | (uint32(key[14]) << 16) | (uint32(key[15]) << 24)
	tmp[4] = uint32(key[16]) | (uint32(key[17]) << 8) | (uint32(key[18]) << 16) | (uint32(key[19]) << 24)
	tmp[5] = uint32(key[20]) | (uint32(key[21]) << 8) | (uint32(key[22]) << 16) | (uint32(key[23]) << 24)
	tmp[6] = uint32(key[24]) | (uint32(key[25]) << 8) | (uint32(key[26]) << 16) | (uint32(key[27]) << 24)
	tmp[7] = uint32(key[28]) | (uint32(key[29]) << 8) | (uint32(key[30]) << 16) | (uint32(key[31]) << 24)

	tmp[8] = uint32(nonce[0]) | (uint32(nonce[1]) << 8) | (uint32(nonce[2]) << 16) | (uint32(nonce[3]) << 24)
	tmp[9] = uint32(nonce[4]) | (uint32(nonce[5]) << 8) | (uint32(nonce[6]) << 16) | (uint32(nonce[7]) << 24)
	tmp[10] = uint32(nonce[8]) | (uint32(nonce[9]) << 8) | (uint32(nonce[10]) << 16) | (uint32(nonce[11]) << 24)
	tmp[11] = uint32(nonce[12]) | (uint32(nonce[13]) << 8) | (uint32(nonce[14]) << 16) | (uint32(nonce[15]) << 24)
	tmp[12] = uint32(nonce[16]) | (uint32(nonce[17]) << 8) | (uint32(nonce[18]) << 16) | (uint32(nonce[19]) << 24)
	tmp[13] = uint32(nonce[20]) | (uint32(nonce[21]) << 8) | (uint32(nonce[22]) << 16) | (uint32(nonce[23]) << 24)
	tmp[14] = uint32(nonce[24]) | (uint32(nonce[25]) << 8) | (uint32(nonce[26]) << 16) | (uint32(nonce[27]) << 24)
	tmp[15] = uint32(nonce[28]) | (uint32(nonce[29]) << 8) | (uint32(nonce[30]) << 16) | (uint32(nonce[31]) << 24)

	// expand key and nonce with the f1 and f2 functions
	// (2.2 https://eprint.iacr.org/2004/092.pdf)
	var f2, f1 uint32
	for i := 16; i < 2560; i++ {
		f1, f2 = tmp[i-15], tmp[i-2]
		f1 = ((f1 >> 7) | (f1 << 25)) ^ ((f1 >> 18) | (f1 << 14)) ^ (f1 >> 3)
		f2 = ((f2 >> 17) | (f2 << 15)) ^ ((f2 >> 19) | (f2 << 13)) ^ (f2 >> 10)
		tmp[i] = f1 + f2 + tmp[i-7] + tmp[i-16] + uint32(i)
	}
	copy(p[:], tmp[512:(512+1024)])
	copy(q[:], tmp[1536:(1536+1024)])

	// do 4096 iterations for initialization
	var ctr uint32
	for i := 0; i < 4096; i++ {
		genKeyStream(&ctr, p, q)
	}
}

func genKeyStream(counter *uint32, p, q *[1024]uint32) uint32 {
	var r, t0, t1, t2, t3 uint32
	ctr := *counter

	j := ctr & mod1024
	if ctr < 1024 {
		t0 = p[(j-3)&mod1024]
		t1 = p[(j-1023)&mod1024]
		t2 = t0 ^ t1

		t0 = (t0 >> 10) | (t0 << 22)
		t1 = (t1 >> 23) | (t1 << 9)
		t3 = t0 ^ t1
		t0 = p[(j-10)&mod1024]
		t1 = q[t2&mod1024]

		p[j] += t0 + t1 + t3

		t3 = p[(j-12)&mod1024]
		t0 = 256 + ((t3 >> 8) & 0xff)
		t1 = 512 + ((t3 >> 16) & 0xff)
		t2 = 768 + ((t3 >> 24) & 0xff)
		t3 = t3 & 0xff

		r = q[t3] + q[t0] + q[t1] + q[t2] ^ p[j]
	} else {
		t0 = q[(j-3)&mod1024]
		t1 = q[(j-1023)&mod1024]
		t2 = t0 ^ t1

		t0 = (t0 >> 10) | (t0 << 22)
		t1 = (t1 >> 23) | (t1 << 9)
		t3 = t0 ^ t1
		t0 = q[(j-10)&mod1024]
		t1 = p[t2&mod1024]

		q[j] += t0 + t1 + t3

		t3 = q[(j-12)&mod1024]
		t0 = 256 + ((t3 >> 8) & 0xff)
		t1 = 512 + ((t3 >> 16) & 0xff)
		t2 = 768 + ((t3 >> 24) & 0xff)
		t3 = t3 & 0xff

		r = p[t3] + p[t0] + p[t1] + p[t2] ^ q[j]
	}

	*counter = (ctr + 1) & mod2048
	return r
}
