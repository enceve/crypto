// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build !amd64

package poly1305

// Sum generates an authenticator for msg using a one-time key
// and puts the 16-byte result into out. Authenticating two
// different messages with the same key allows an attacker
// to forge messages at will.
func Sum(out *[TagSize]byte, msg []byte, key *[32]byte) {
	p := new(polyHash)
	initialize(&(p.r), &(p.pad), key)

	p.Write(msg)

	if p.off > 0 {
		p.buf[p.off] = 1 // invariant: p0.off < TagSize
		for i := p.off + 1; i < TagSize; i++ {
			p.buf[i] = 0
		}
		core(p.buf[:], finalBlock, &(p.h), &(p.r))
	}

	finalize(out, &(p.h), &(p.pad))
}
