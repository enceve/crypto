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
		t.Fatal(err)
	}
	// Bobs private part
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

	xA, yA := a.DeriveSecret(B)
	xB, yB := b.DeriveSecret(A)

	if xA.Cmp(xB) != 0 {
		t.Fatal("ecdh: key exchange failed - secret X coordinates not equal")
	}
	if yA.Cmp(yB) != 0 {
		t.Fatal("ecdh: key exchange failed - secret Y coordinates not equal")
	}
}
