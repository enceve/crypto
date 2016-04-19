// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The ecdh package implements the Diffie-Hellman key
// exchange with elliptic curves. This implementation
// can be used with generic elliptic curves provided
// by the crypto.elliptic package or with D. J.
// Bernsteins Curve25519.
package ecdh

import (
	"crypto/elliptic"
	"io"
	"math/big"
)

// ECPoint represents a point on an elliptic curve.
type ECPoint struct {
	X *big.Int // The X coordinate of the point.
	Y *big.Int // The Y coordinate of the point.
}

// Generic represents a generic elliptic curve.
type Generic struct {
	Curve elliptic.Curve // The elliptic curve
}

// GenerateKey returns a private/public key pair for
// the elliptic curve. The given reader must
// return random data.
func (g *Generic) GenerateKey(rand io.Reader) (private []byte, public ECPoint, err error) {
	private, x, y, err := elliptic.GenerateKey(g.Curve, rand)
	if err != nil {
		private = nil
		return
	}
	public = ECPoint{x, y}
	return
}

// Returns true if the given point is on the elliptic curve.
func (g *Generic) IsOnCurve(point ECPoint) bool {
	return g.Curve.IsOnCurve(point.X, point.Y)
}

// ComputeSecret returns the elliptic curve point computed form
// the own private and the peers public key. This function
// does the Diffie-Hellman exchange.
func (g *Generic) ComputeSecret(private []byte, peersPublic ECPoint) ECPoint {
	x, y := g.Curve.ScalarMult(peersPublic.X, peersPublic.Y, private)
	return ECPoint{x, y}
}
