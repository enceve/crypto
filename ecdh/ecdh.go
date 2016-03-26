// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The ecdh package implements the Diffie-Hellman key
// exchange with elliptic curves. This implementation
// can be used with any elliptic curve. Recommened are
// the Curve25529 and the Edward`s curve Ed25519.
package ecdh

import (
	"crypto/elliptic"
	"errors"
	"io"
	"math/big"
)

// The public part of the EC-Diffie-Hellman exchange
// consisting of the elliptic curve, the public X and
// the public Y coordinate.
type Public struct {
	Curve elliptic.Curve
	X, Y  *big.Int
}

// The private part of the EC-Diffie-Hellman exchange
// consisting of the private vlaue in big-endian format.
type Private struct {
	Value []byte
}

// Creates a new public part form an elliptic curve.
func NewPublic(c elliptic.Curve) *Public {
	return &Public{Curve: c}
}

// GenerateKey returns a public/private key pair. The private key is
// generated using the given reader, which must return random data.
// If the pub argument is nil, the functions panics.
func GenerateKey(pub *Public, random io.Reader) (*Private, error) {
	if pub == nil {
		panic("public part is nil")
	}

	priv, x, y, err := elliptic.GenerateKey(pub.Curve, random)
	if err != nil {
		return nil, err
	}
	pub.X = x
	pub.Y = y

	return &Private{Value: priv}, nil
}

// Validates the parameters for the EC-Diffie-Hellman exchange.
// If the given parameters cannot used for a secret derivation,
// this function returns an non-nil error.
// Only if the return value is nil, the DeriveSecret function will
// work correctly.
func (pri *Private) Validate(pub *Public) error {
	if pub == nil {
		return errors.New("public part is nil")
	}
	if pub.X == nil {
		return errors.New("public X coordinate is nil")
	}
	if pub.Y == nil {
		return errors.New("public Y coordinate is nil")
	}

	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return errors.New("public point (X/Y) not on curve")
	}
	return nil
}

// DeriveSecret does the  EC-Diffie-Hellman exchange.
// The public part contains the elliptic curve, the X and
// the Y coordinate of public value from the other side.
// If the pub argument is nil, the functions panics.
// This function does not validate the parameters. Therefore
// use Validate.
func (pri *Private) DeriveSecret(pub *Public) (x, y *big.Int) {
	if pub == nil {
		panic("public part is nil")
	}

	x, y = pub.Curve.ScalarMult(pub.X, pub.Y, pri.Value)
	return
}
