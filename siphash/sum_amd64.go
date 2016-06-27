// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build amd64, !cgo, !appengine

package siphash

import (
	"hash"
	"unsafe"
)

// New returns a hash.Hash64 computing the SipHash checksum with a 128 bit key.
func New(key *[16]byte) hash.Hash64 {
	h := new(hashFunc)
	h.key[0] = *(*uint64)(unsafe.Pointer(&key[0]))
	h.key[1] = *(*uint64)(unsafe.Pointer(&key[8]))
	h.Reset()
	return h
}

// Sum generates an authenticator for msg with a 128 bit key
// and puts the 64 bit result into out.
func Sum(out *[TagSize]byte, msg []byte, key *[16]byte) {
	(*[1]uint64)(unsafe.Pointer(&out[0]))[0] = Sum64(msg, key)
}

// Sum64 generates and returns the 64 bit authenticator
// for msg with a 128 bit key.
func Sum64(msg []byte, key *[16]byte) uint64 {
	k0 := *(*uint64)(unsafe.Pointer(&key[0]))
	k1 := *(*uint64)(unsafe.Pointer(&key[8]))

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
