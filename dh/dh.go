// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The dh package implements the Diffie-Hellman key
// exchange.
package dh

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

// The public part of the Diffie-Hellman exchange
// consisting of the prime, the generator and the
// public value.
type Public struct {
	P     *big.Int // The prime
	G     *big.Int // The generator
	Value *big.Int // The public value
}

// The private part of the Diffie-Hellman exchange
// consisting the private value
type Private struct {
	Value *big.Int // The private value
}

var one *big.Int = big.NewInt(1)
var two *big.Int = big.NewInt(2)

// Determines whether the prime of the public
// part is or is not a "safe prime". A so called
// "safe prime" is a prime number p for which following
// statement is true:
// The number q = ( p - 1 ) / 2 is prime.
// The n argument is the number of iterations for the
// probabilistic prime test.
// If the pub argument or the prime is nil, the function
// panics.
func (pub *Public) SafePrime(n int) bool {
	if pub == nil {
		panic("dh: pub is nil")
	}
	if pub.P == nil {
		panic("dh: pub.P is nil")
	}
	q := new(big.Int).Sub(pub.P, one)
	q = q.Div(q, two)
	return q.ProbablyPrime(n)
}

// GenerateKey returns a public/private key pair. The private key is
// generated using the given reader, which must return random data.
// An error is returned, if the prime or the generator is nil,
// or the reader fails.
// If the pub argument is nil, the functions panics.
func GenerateKey(pub *Public, random io.Reader) (*Private, error) {
	if pub == nil {
		panic("dh: public part is nil")
	}
	if pub.P == nil {
		return nil, errors.New("dh: public prime is nil")
	}
	if pub.G == nil {
		return nil, errors.New("dh: public generator is nil")
	}

	pri := new(Private)
	pv, err := rand.Int(random, pub.P)
	if err != nil {
		return nil, err
	}
	pri.Value = pv

	pub.Value = new(big.Int).Exp(pub.G, pri.Value, pub.P)
	return pri, nil
}

// Validates the parameters for the Diffie-Hellman exchange.
// If the given parameters cannot used for a secret derivation,
// this function returns an non-nil error.
// Only if the return value is nil, the DeriveSecret function will
// work correctly.
func (pri *Private) Validate(pub *Public) error {
	if pub == nil {
		return errors.New("dh: public part is nil")
	}

	if pri.Value == nil {
		return errors.New("dh: private value is nil")
	}
	if pub.P == nil {
		return errors.New("dh: public prime is nil")
	}
	if pub.Value == nil {
		return errors.New("dh: public value is nil")
	}

	if pub.G.Cmp(pub.P) >= 0 {
		return errors.New("dh: generator >= prime")
	}
	if pub.Value.Cmp(pub.P) >= 0 {
		return errors.New("dh: public value >= prime")
	}
	if pri.Value.Cmp(pub.P) >= 0 {
		return errors.New("dh: private value >= prime")
	}
	return nil
}

// DeriveSecret does the  Diffie-Hellman exchange.
// The public part contains the prime, the generator and the
// public value of the other side.
// If the pub argument is nil, the functions panics.
// This function does not validate the parameters. Therefore
// use Validate.
func (pri *Private) DeriveSecret(pub *Public) *big.Int {
	if pub == nil {
		panic("dh: public part is nil")
	}

	return new(big.Int).Exp(pub.Value, pri.Value, pub.P)
}
