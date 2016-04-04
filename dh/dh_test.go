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
	pub := RFC3526_1536()
	if !pub.P.ProbablyPrime(32) {
		t.Fatal("dh: RFC3526_1536 is not prime")
	}
	if !pub.SafePrime(32) {
		t.Fatal("dh: RFC3526_1536 is not a safe prime")
	}

	pub = RFC3526_2048()
	if !pub.P.ProbablyPrime(32) {
		t.Fatal("dh: RFC3526_2048 is not prime")
	}
	if !pub.SafePrime(32) {
		t.Fatal("dh: RFC3526_2048 is not a safe prime")
	}

	pub = RFC3526_3072()
	if !pub.P.ProbablyPrime(32) {
		t.Fatal("dh: RFC3526_3072 is not prime")
	}
	if !pub.SafePrime(32) {
		t.Fatal("dh: RFC3526_3072 is not a safe prime")
	}

	pub = RFC3526_4096()
	if !pub.P.ProbablyPrime(32) {
		t.Fatal("dh: RFC3526_4096 is not prime")
	}
	if !pub.SafePrime(32) {
		t.Fatal("dh: RFC3526_4096 is not a safe prime")
	}
}

// A Diffie-Hellman exchange example.
func TestDHExample(t *testing.T) {
	// Alice
	A := RFC3526_2048()
	a, err := GenerateKey(A, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate alice's private / public value - Cause: %s", err)
	}

	// Bob
	B := RFC3526_2048()
	b, err := GenerateKey(B, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate bob's private / public value - Cause: %s", err)
	}

	if err := a.Validate(B); err != nil {
		t.Fatalf("Alice failed to verify bob's public value - Cause: %s", err)
	}
	if err := b.Validate(A); err != nil {
		t.Fatalf("Bob failed to verify alice's public value - Cause: %s", err)
	}

	skA := a.DeriveSecret(B)
	skB := b.DeriveSecret(A)

	if skA.Cmp(skB) != 0 {
		t.Fatalf("key exchange failed - secrets not equal\nAlice: %v\nBob  : %v", skA, skB)
	}
}

func Benchmark2048(b *testing.B) {
	pubAlice := RFC3526_2048()
	priAlice, err := GenerateKey(pubAlice, rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate alice's private value - Cause: %s", err)
	}
	pubBob := RFC3526_2048()
	_, err = GenerateKey(pubBob, rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate bob's private value - Cause: %s", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		priAlice.DeriveSecret(pubBob)
	}
}

func Benchmark4096(b *testing.B) {
	pubAlice := RFC3526_4096()
	priAlice, err := GenerateKey(pubAlice, rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate alice's private value - Cause: %s", err)
	}
	pubBob := RFC3526_4096()
	_, err = GenerateKey(pubBob, rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate bob's private value - Cause: %s", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		priAlice.DeriveSecret(pubBob)
	}
}
