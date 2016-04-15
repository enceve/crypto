// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package dh

import (
	"crypto/rand"
	"testing"
)

// Tests all predefined primes and
// their "safe prime" characteristic.
func TestPrimes(t *testing.T) {
	g := RFC3526_2048()
	if !g.P.ProbablyPrime(32) {
		t.Fatal("RFC3526_2048 is not prime")
	}
	if !IsSafePrime(g, 32) {
		t.Fatal("RFC3526_2048 is not a safe prime")
	}

	g = RFC3526_3072()
	if !g.P.ProbablyPrime(32) {
		t.Fatal("RFC3526_3072 is not prime")
	}
	if !IsSafePrime(g, 32) {
		t.Fatal("RFC3526_3072 is not a safe prime")
	}

	g = RFC3526_4096()
	if !g.P.ProbablyPrime(32) {
		t.Fatal("RFC3526_4096 is not prime")
	}
	if !IsSafePrime(g, 32) {
		t.Fatal("RFC3526_4096 is not a safe prime")
	}
}

// A Diffie-Hellman exchange example.
func TestDHExample(t *testing.T) {
	group := RFC3526_2048()

	// Alice
	alicePrivate, alicePublic, err := group.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate alice's private / public key pair: %s", err)
	}

	// Bob
	bobPrivate, bobPublic, err := group.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate bob's private / public key pair: %s", err)
	}

	secretAlice := group.ComputeSecret(alicePrivate, bobPublic)
	secretBob := group.ComputeSecret(bobPrivate, alicePublic)

	if secretAlice.Cmp(secretBob) != 0 {
		t.Fatalf("key exchange failed - secrets not equal\nAlice: %v\nBob  : %v", secretAlice, secretBob)
	}
}

func BenchmarkGenerateKey2048(b *testing.B) {
	group := RFC3526_2048()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := group.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatal("Failed to generate private / public key pair")
		}
	}
}

func Benchmark2048(b *testing.B) {
	group := RFC3526_2048()
	alicePrivate, _, err := group.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate alice's private / public key: %s", err)
	}
	_, bobPublic, err := group.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate bob's private / public key: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		group.ComputeSecret(alicePrivate, bobPublic)
	}
}

func Benchmark4096(b *testing.B) {
	group := RFC3526_4096()
	alicePrivate, _, err := group.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate alice's private / public key: %s", err)
	}
	_, bobPublic, err := group.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate bob's private / public key: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		group.ComputeSecret(alicePrivate, bobPublic)
	}
}
