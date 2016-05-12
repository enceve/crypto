// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package ecdh

import (
	"io"

	"golang.org/x/crypto/curve25519"
)

// Curve25519 represents D. J. Bernstein's elliptic curve 25519.
type Curve25519 struct{}

// GenerateKey returns a private/public key pair for
// Curve25519. The given reader must return random data.
func (c *Curve25519) GenerateKey(rand io.Reader) (private, public *[32]byte, err error) {
	private = new([32]byte)
	_, err = io.ReadFull(rand, private[:])
	if err != nil {
		private = nil
		return
	}
	// From https://cr.yp.to/ecdh.html
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64

	public = new([32]byte)
	curve25519.ScalarBaseMult(public, private)
	return
}

// Computes the secret value from the own private key and
// the peers public key. This function does the Diffie-Hellman
// exchange.
func (c *Curve25519) ComputeSecret(secret, private, peersPublic *[32]byte) {
	curve25519.ScalarMult(secret, private, peersPublic)
}
