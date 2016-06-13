// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package dh implements the Diffie-Hellman key exchange over
// multiplicative groups of integers modulo a prime.
// This also defines some commen groups described in RFC 3526.
package dh

import (
	cryptorand "crypto/rand"
	"errors"
	"io"
	"math/big"
)

var zero *big.Int = big.NewInt(0)
var one *big.Int = big.NewInt(1)
var two *big.Int = big.NewInt(2)

// IsSafePrime returns true, if the prime of the group is
// a so called safe-prime. For a group with a safe-prime prime
// number the Decisional-Diffie-Hellman-Problem (DDH) is a
// 'hard' problem. The n argument is the number of iterations
// for the probabilistic prime test.
// It's recommend to use DDH-safe groups for DH-exchanges.
func IsSafePrimeGroup(g *Group, n int) bool {
	q := new(big.Int).Sub(g.P, one)
	q = q.Div(q, two)
	return q.ProbablyPrime(n)
}

// PublicKey is the type of DH public keys.
type PublicKey *big.Int

// PrivateKey is the type of DH private keys.
type PrivateKey *big.Int

// Group represents a mathematical group defined
// by a large prime and a generator.
type Group struct {
	P *big.Int // The prime
	G *big.Int // The generator
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func (g *Group) GenerateKey(rand io.Reader) (private PrivateKey, public PublicKey, err error) {
	if g.P == nil {
		panic("crypto/dh: group prime is nil")
	}
	if g.G == nil {
		panic("crypto/dh: group generator is nil")
	}
	if rand == nil {
		rand = cryptorand.Reader
	}

	// Ensure, that p.G ^ privateKey > than g.P
	// (only modulo calculations are safe)
	// The minimal (and common) value for p.G is 2
	// So 2 ^ (1 + 'bitsize of p.G') > than g.P
	min := big.NewInt(int64(g.P.BitLen() + 1))
	bytes := make([]byte, (g.P.BitLen()+7)/8)

	for private == nil {
		_, err = io.ReadFull(rand, bytes)
		if err != nil {
			private = nil
			return
		}
		// Clear bits in the first byte to increase
		// the probability that the candidate is < g.P.
		bytes[0] = 0
		if private == nil {
			private = new(big.Int)
		}
		(*private).SetBytes(bytes)
		if (*private).Cmp(min) < 0 {
			private = nil
		}
	}

	public = new(big.Int).Exp(g.G, private, g.P)
	return
}

// PublicKey returns the public key corresponding to the given private one.
func (g *Group) PublicKey(private PrivateKey) (public PublicKey) {
	public = new(big.Int).Exp(g.G, private, g.P)
	return
}

//private returns a non-nil error if the given public key is
// not a possible element of the group. This means, that the
// public key is < 0 or > g.P.
func (g *Group) Check(peersPublic PublicKey) (err error) {
	if !((*peersPublic).Cmp(zero) >= 0 && (*peersPublic).Cmp(g.P) == -1) {
		err = errors.New("peer's public is not a possible group element")
	}
	return
}

// ComputeSecret returns the secret computed from
// the own private and the peer's public key.
func (g *Group) ComputeSecret(private PrivateKey, peersPublic PublicKey) (secret *big.Int) {
	secret = new(big.Int).Exp(peersPublic, private, g.P)
	return
}
