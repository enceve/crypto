// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package poly1305 implements Poly1305 one-time message authentication code as
// specified in http://cr.yp.to/mac/poly1305-20050329.pdf.
//
// Poly1305 is a fast, one-time authentication function. It is infeasible for an
// attacker to generate an authenticator for a message without the key.
// However, a key must only be used for a single message. Authenticating two
// different messages with the same key allows an attacker to forge
// authenticators for other messages with the same key.
//
// Poly1305 was originally coupled with AES in order to make Poly1305-AES.
// AES was used with a fixed key in order to generate one-time keys from an
// nonce. However, in this package AES isn't used and the one-time key is
// specified directly.
package poly1305

import (
	"crypto/subtle"
	"errors"
)

// The size of the poly1305 authentication tag in bytes.
const TagSize = 16

const (
	msgBlock   = uint32(1 << 24)
	finalBlock = uint32(0)
)

// Verify returns true if and only if the mac is a valid authenticator
// for msg with the given key.
func Verify(mac *[TagSize]byte, msg []byte, key *[32]byte) bool {
	var sum [TagSize]byte
	Sum(&sum, msg, key)
	return subtle.ConstantTimeCompare(sum[:], mac[:]) == 1
}

// New returns a hash.Hash computing the poly1305 sum.
// Notice that Poly1305 is inseure if one key is used twice.
func New(key *[32]byte) *Hash {
	p := new(Hash)
	initialize(&(p.r), &(p.pad), key)
	return p
}

var writeAfterSumErr error = errors.New("checksum already computed - adding more data is not allowed")

// Hash implements a Poly1305 writer interface.
// Poly1305 cannot used like common hash.Hash implementations,
// beause of using a Poly1305 key twice breaks its security.
// So poly1305.Hash does not support some kind of reset.
type Hash struct {
	h, r [5]uint32
	pad  [4]uint32

	buf  [TagSize]byte
	off  int
	done bool
}

// Write adds more data to the running Poly1305 hash.
// This function returns an non-nil error, if a call
// to Write happens after the hash's Sum function was
// called. So it's not possible to compute the checksum
// and than add more data.
func (p *Hash) Write(msg []byte) (int, error) {
	if p.done {
		return 0, writeAfterSumErr
	}
	n := len(msg)

	diff := TagSize - p.off
	if p.off > 0 {
		p.off += copy(p.buf[p.off:], msg[:diff])
		if p.off == TagSize {
			core(p.buf[:], msgBlock, &(p.h), &(p.r))
			p.off = 0
		}
		msg = msg[diff:]
	}

	length := len(msg) & (^(TagSize - 1))
	if length > 0 {
		core(msg[:length], msgBlock, &(p.h), &(p.r))
		msg = msg[length:]
	}
	if len(msg) > 0 {
		p.off += copy(p.buf[p.off:], msg)
	}

	return n, nil
}

// Sum computes the Poly1305 checksum of the prevouisly
// proccessed data and writes it to out. It is legal to
// call this function more than one time.
func (p *Hash) Sum(out *[TagSize]byte) {
	h, r := p.h, p.r
	pad := p.pad

	if p.off > 0 {
		var buf [TagSize]byte
		copy(buf[:], p.buf[:p.off])
		buf[p.off] = 1 // invariant: p.off < TagSize

		core(buf[:], finalBlock, &h, &r)
	}

	finalize(out, &h, &pad)
	p.done = true
}

func finalize(tag *[TagSize]byte, h *[5]uint32, pad *[4]uint32) {
	var g0, g1, g2, g3, g4 uint32

	// fully carry h
	h0, h1, h2, h3, h4 := h[0], h[1], h[2], h[3], h[4]

	h2 += h1 >> 26
	h1 &= 0x3ffffff
	h3 += h2 >> 26
	h2 &= 0x3ffffff
	h4 += h3 >> 26
	h3 &= 0x3ffffff
	h0 += 5 * (h4 >> 26)
	h4 &= 0x3ffffff
	h1 += h0 >> 26
	h0 &= 0x3ffffff

	// h + -p
	g0 = h0 + 5

	g1 = h1 + (g0 >> 26)
	g0 &= 0x3ffffff
	g2 = h2 + (g1 >> 26)
	g1 &= 0x3ffffff
	g3 = h3 + (g2 >> 26)
	g2 &= 0x3ffffff
	g4 = h4 + (g3 >> 26) - (1 << 26)
	g3 &= 0x3ffffff

	// select h if h < p else h + -p
	mask := (g4 >> (32 - 1)) - 1
	g0 &= mask
	g1 &= mask
	g2 &= mask
	g3 &= mask
	g4 &= mask
	mask = ^mask
	h0 = (h0 & mask) | g0
	h1 = (h1 & mask) | g1
	h2 = (h2 & mask) | g2
	h3 = (h3 & mask) | g3
	h4 = (h4 & mask) | g4

	// h %= 2^128
	h0 |= h1 << 26
	h1 = ((h1 >> 6) | (h2 << 20))
	h2 = ((h2 >> 12) | (h3 << 14))
	h3 = ((h3 >> 18) | (h4 << 8))

	// tag = (h + pad) % (2^128)
	f := uint64(h0) + uint64(pad[0])
	h0 = uint32(f)
	f = uint64(h1) + uint64(pad[1]) + (f >> 32)
	h1 = uint32(f)
	f = uint64(h2) + uint64(pad[2]) + (f >> 32)
	h2 = uint32(f)
	f = uint64(h3) + uint64(pad[3]) + (f >> 32)
	h3 = uint32(f)

	extractHash(tag, h0, h1, h2, h3)
}
