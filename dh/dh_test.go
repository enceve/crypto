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
		t.Fatal(err)
	}

	// Bob
	B := RFC3526_2048()
	b, err := GenerateKey(B, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if err := a.Validate(B); err != nil {
		t.Fatal(err)
	}
	if err := b.Validate(A); err != nil {
		t.Fatal(err)
	}

	skA := a.DeriveSecret(B)
	skB := b.DeriveSecret(A)

	if skA.Cmp(skB) != 0 {
		t.Fatal("dh: key exchange failed - secrets not equal")
	}
}
