// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package hc128 implements the stream cipher
// HC-128 from the eSTREAM portfolio (software)
// designed by Hongjun Wu.
package hc128 // import "github.com/enceve/crypto/hc128"

import "crypto/cipher"

const (
	mod512  uint32 = 0x1FF
	mod1024 uint32 = 0x3FF
)

// NewCipher returns a new cipher.Stream implementing the
// HC-128 cipher with the given key and nonce.
func NewCipher(nonce, key *[16]byte) cipher.Stream {
	c := new(streamCipher)
	initialize(nonce, key, &(c.p), &(c.q))
	return c
}

type streamCipher struct {
	p, q      [512]uint32
	ctr       uint32
	keyStream [4]byte
	off       int
}

func initialize(nonce, key *[16]byte, p, q *[512]uint32) {
	var tmp [1280]uint32

	tmp[0] = uint32(key[0]) | (uint32(key[1]) << 8) | (uint32(key[2]) << 16) | (uint32(key[3]) << 24)
	tmp[1] = uint32(key[4]) | (uint32(key[5]) << 8) | (uint32(key[6]) << 16) | (uint32(key[7]) << 24)
	tmp[2] = uint32(key[8]) | (uint32(key[9]) << 8) | (uint32(key[10]) << 16) | (uint32(key[11]) << 24)
	tmp[3] = uint32(key[12]) | (uint32(key[13]) << 8) | (uint32(key[14]) << 16) | (uint32(key[15]) << 24)
	copy(tmp[4:8], tmp[0:4])

	tmp[8] = uint32(nonce[0]) | (uint32(nonce[1]) << 8) | (uint32(nonce[2]) << 16) | (uint32(nonce[3]) << 24)
	tmp[9] = uint32(nonce[4]) | (uint32(nonce[5]) << 8) | (uint32(nonce[6]) << 16) | (uint32(nonce[7]) << 24)
	tmp[10] = uint32(nonce[8]) | (uint32(nonce[9]) << 8) | (uint32(nonce[10]) << 16) | (uint32(nonce[11]) << 24)
	tmp[11] = uint32(nonce[12]) | (uint32(nonce[13]) << 8) | (uint32(nonce[14]) << 16) | (uint32(nonce[15]) << 24)
	copy(tmp[12:16], tmp[8:12])

	// expand key and nonce with the f1 and f2 functions
	// (2.2 http://www.ecrypt.eu.org/stream/p3ciphers/hc/hc128_p3.pdf)
	var f2, f1 uint32
	for i := 16; i < 1280; i++ {
		f1, f2 = tmp[i-15], tmp[i-2]
		f1 = ((f1 >> 7) | (f1 << 25)) ^ ((f1 >> 18) | (f1 << 14)) ^ (f1 >> 3)
		f2 = ((f2 >> 17) | (f2 << 15)) ^ ((f2 >> 19) | (f2 << 13)) ^ (f2 >> 10)
		tmp[i] = f1 + f2 + tmp[i-7] + tmp[i-16] + uint32(i)
	}
	copy(p[:], tmp[256:(256+512)])
	copy(q[:], tmp[768:(768+512)])

	// do 1024 iterations for initialization
	var ctr uint32
	for i := range p {
		p[i] = genKeyStream(&ctr, p, q)
	}
	for i := range q {
		q[i] = genKeyStream(&ctr, p, q)
	}
}

func genKeyStream(counter *uint32, p, q *[512]uint32) uint32 {
	var r, t0, t1, t2, t3 uint32
	ctr := *counter

	j := ctr & mod512
	if ctr < 512 {
		t0 = p[(j-3)&mod512]
		t1 = p[(j-10)&mod512]
		t2 = p[(j-511)&mod512]
		t3 = p[(j-12)&mod512]

		t0 = ((t0 >> 10) | (t0 << 22))
		t1 = ((t1 >> 8) | (t1 << 24))
		t2 = ((t2 >> 23) | (t2 << 9))
		p[j] += (t0 ^ t2) + t1

		t0 = t3 & 0xff
		t1 = 256 + (t3>>16)&0xff
		r = (q[t0] + q[t1]) ^ p[j]
	} else {
		t0 = q[(j-3)&mod512]
		t1 = q[(j-10)&mod512]
		t2 = q[(j-511)&mod512]
		t3 = q[(j-12)&mod512]

		t0 = ((t0 << 10) | (t0 >> 22))
		t1 = ((t1 << 8) | (t1 >> 24))
		t2 = ((t2 << 23) | (t2 >> 9))
		q[j] += (t0 ^ t2) + t1

		t0 = t3 & 0xff
		t1 = 256 + (t3>>16)&0xff
		r = p[t0] + p[t1] ^ q[j]
	}

	*counter = (ctr + 1) & mod1024
	return r
}
