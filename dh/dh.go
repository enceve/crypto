// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The dh package implements the Diffie-Hellman key
// exchange.
package dh

import (
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
func IsSafePrime(g *Group, n int) bool {
	q := new(big.Int).Sub(g.P, one)
	q = q.Div(q, two)
	return q.ProbablyPrime(n)
}

// Group represents a mathematical group defined
// by a large prime and a generator.
type Group struct {
	P *big.Int // The prime
	G *big.Int // The generator
}

// GenerateKey returns a public/private key pair. The private key is
// generated using the given reader, which must return random data.
func (g *Group) GenerateKey(rand io.Reader) (private, public *big.Int, err error) {
	if g.P == nil {
		panic("group prime is nil")
	}
	if g.G == nil {
		panic("group generator is nil")
	}

	// Ensure, that p.G ** private > than g.P
	// (only modulo calculations are safe)
	// The minimal (and common) value for p.G is 2
	// So 2 ** (1 + 'bitsize of p.G') > than g.P
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
		private.SetBytes(bytes)
		if private.Cmp(min) < 0 {
			private = nil
		}
	}
	public = new(big.Int).Exp(g.G, private, g.P)
	return
}

// IsGroupElement returns true if the given public key is
// a possible element of the group. This means, that the
// public key is >= 0 and < g.P.
func (g *Group) IsGroupElement(peersPublic *big.Int) bool {
	return peersPublic.Cmp(zero) >= 0 && peersPublic.Cmp(g.P) == -1
}

// ComputeSecret returns the secret computed from
// the own private and the peer's public key.
func (g *Group) ComputeSecret(private, peersPublic *big.Int) *big.Int {
	return new(big.Int).Exp(peersPublic, private, g.P)
}
