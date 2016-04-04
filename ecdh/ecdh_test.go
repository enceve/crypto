// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package ecdh

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// An example for the EC-DH key-exchange using the curve P256.
func TestECDHExample(t *testing.T) {
	// Alices public part
	A := NewPublic(elliptic.P256())
	// Bobs public part
	B := NewPublic(elliptic.P256())

	// Alices private part
	a, err := GenerateKey(A, rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate alice's private / public value - Cause: %s", err)
	}
	// Bobs private part
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

	xA, yA := a.DeriveSecret(B)
	xB, yB := b.DeriveSecret(A)

	if xA.Cmp(xB) != 0 {
		t.Fatalf("key exchange failed - secret X coordinates not equal\nAlice: %v\nBob  : %v", xA, xB)
	}
	if yA.Cmp(yB) != 0 {
		t.Fatalf("key exchange failed - secret Y coordinates not equal\nAlice: %v\nBob  : %v", yA, yB)
	}
}

func BenchmarkP256(b *testing.B) {
	pubAlice := NewPublic(elliptic.P256())
	priAlice, err := GenerateKey(pubAlice, rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate alice's private value - Cause: %s", err)
	}
	pubBob := NewPublic(elliptic.P256())
	_, err = GenerateKey(pubBob, rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate bob's private value - Cause: %s", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		priAlice.DeriveSecret(pubBob)
	}
}

func BenchmarkP521(b *testing.B) {
	pubAlice := NewPublic(elliptic.P521())
	priAlice, err := GenerateKey(pubAlice, rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate alice's private value - Cause: %s", err)
	}
	pubBob := NewPublic(elliptic.P521())
	_, err = GenerateKey(pubBob, rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate bob's private value - Cause: %s", err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		priAlice.DeriveSecret(pubBob)
	}
}
