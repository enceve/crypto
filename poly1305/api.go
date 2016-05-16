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
	"hash"

	"github.com/EncEve/crypto"
)

// The size of the poly1305 authentication tag in bytes.
const TagSize = 16

// Verify returns true if and only if the mac is a valid authenticator
// for msg with the given key.
func Verify(mac *[TagSize]byte, msg []byte, key *[32]byte) bool {
	var sum [TagSize]byte
	Sum(&sum, msg, key)
	return subtle.ConstantTimeCompare(sum[:], mac[:]) == 1
}

// New returns a hash.Hash computing the poly1305 sum.
// The given key must be 256 bit (32 byte). Notice that
// poly1305 is inseure if one key is used twice. To prevent
// misuse the returned hash.Hash doesn't support the Reset()
// method.
func New(key []byte) (hash.Hash, error) {
	if k := len(key); k != 32 {
		return nil, crypto.KeySizeError(k)
	}
	var k [32]byte
	copy(k[:], key)

	p := new(polyHash)
	initialize(&(p.r), &(p.pad), &k)
	return p, nil
}

// The poly1305 hash struct implementing hash.Hash
type polyHash struct {
	h, r [5]uint32
	pad  [4]uint32

	buf [TagSize]byte
	off int
}

func (p *polyHash) BlockSize() int { return TagSize }

func (p *polyHash) Size() int { return TagSize }

func (p *polyHash) Reset() {
	panic("poly1305 does not support Reset() - poly1305 is insecure if one key is used twice!")
}

func (p *polyHash) Write(msg []byte) (int, error) {
	n := len(msg)

	diff := TagSize - p.off
	if p.off > 0 {
		p.off += copy(p.buf[p.off:], msg[:diff])
		if p.off == TagSize {
			polyCore(p.buf[:], msgBlock, &(p.h), &(p.r))
			p.off = 0
		}
		msg = msg[diff:]
	}

	length := len(msg) & (^(TagSize - 1))
	if length > 0 {
		polyCore(msg[:length], msgBlock, &(p.h), &(p.r))
		msg = msg[length:]
	}
	if len(msg) > 0 {
		p.off += copy(p.buf[p.off:], msg)
	}

	return n, nil
}

func (p *polyHash) Sum(b []byte) []byte {
	var mac [TagSize]byte
	p0 := *p

	if p0.off > 0 {
		p0.buf[p0.off] = 1 // invariant: p0.off < TagSize
		for i := p0.off + 1; i < TagSize; i++ {
			p0.buf[i] = 0
		}
		polyCore(p0.buf[:], finalBlock, &(p0.h), &(p0.r))
	}

	polyFinalize(&mac, &(p0.h), &(p0.pad))
	return append(b, mac[:]...)
}
