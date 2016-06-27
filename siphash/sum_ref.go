// +build !amd64

package siphash

import "hash"

// New returns a hash.Hash64 computing the SipHash checksum with a 128 bit key.
func New(key *[16]byte) hash.Hash64 {
	h := new(hashFunc)
	h.key[0] = uint64(key[0]) | uint64(key[1])<<8 | uint64(key[2])<<16 | uint64(key[3])<<24 |
		uint64(key[4])<<32 | uint64(key[5])<<40 | uint64(key[6])<<48 | uint64(key[7])<<56
	h.key[1] = uint64(key[8]) | uint64(key[9])<<8 | uint64(key[10])<<16 | uint64(key[11])<<24 |
		uint64(key[12])<<32 | uint64(key[13])<<40 | uint64(key[14])<<48 | uint64(key[15])<<56
	h.Reset()
	return h
}

// Sum generates an authenticator for msg with a 128 bit key
// and puts the 64 bit result into out.
func Sum(out *[TagSize]byte, msg []byte, key *[16]byte) {
	r := Sum64(msg, key)

	out[0] = byte(r)
	out[1] = byte(r >> 8)
	out[2] = byte(r >> 16)
	out[3] = byte(r >> 24)
	out[4] = byte(r >> 32)
	out[5] = byte(r >> 40)
	out[6] = byte(r >> 48)
	out[7] = byte(r >> 56)
}

// Sum64 generates and returns the 64 bit authenticator
// for msg with a 128 bit key.
func Sum64(msg []byte, key *[16]byte) uint64 {
	k0 := uint64(key[0]) | uint64(key[1])<<8 | uint64(key[2])<<16 | uint64(key[3])<<24 |
		uint64(key[4])<<32 | uint64(key[5])<<40 | uint64(key[6])<<48 | uint64(key[7])<<56
	k1 := uint64(key[8]) | uint64(key[9])<<8 | uint64(key[10])<<16 | uint64(key[11])<<24 |
		uint64(key[12])<<32 | uint64(key[13])<<40 | uint64(key[14])<<48 | uint64(key[15])<<56

	var hVal [4]uint64
	hVal[0] = k0 ^ c0
	hVal[1] = k1 ^ c1
	hVal[2] = k0 ^ c2
	hVal[3] = k1 ^ c3

	n := len(msg)
	ctr := byte(n)

	if n >= TagSize {
		n &= (^(TagSize - 1))
		core(&hVal, msg[:n])
		msg = msg[n:]
	}

	var block [TagSize]byte
	for i, v := range msg {
		block[i] = v
	}
	block[7] = ctr

	return finalize(&hVal, &block)
}
