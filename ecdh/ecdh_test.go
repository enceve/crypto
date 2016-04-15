// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package ecdh

import (
	"crypto/elliptic"
	"crypto/rand"
	"testing"
)

// An example for the ECDH key-exchange using the curve P256.
func TestECDHExample(t *testing.T) {
	p256 := &Generic{elliptic.P256()}

	privateAlice, publicAlice, err := p256.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
	}

	privateBob, publicBob, err := p256.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Bob's private/public key pair: %s", err)
	}

	// Alice computes the Diffie-Hellman secret with her private and Bob's
	// public key.
	if !p256.IsOnCurve(publicBob) {
		t.Fatal("Bob's public key is not on the curve")
	}
	secretAlice := p256.ComputeSecret(privateAlice, publicBob)

	// Bob computes the Diffie-Hellman secret with his private and Alice's
	// public key.
	if !p256.IsOnCurve(publicAlice) {
		t.Fatal("Bob's public key is not on the curve")
	}
	secretBob := p256.ComputeSecret(privateBob, publicAlice)

	// Verify if the computes secret are equal
	if secretAlice.X.Cmp(secretBob.X) != 0 {
		t.Fatalf("key exchange failed - secret X coordinates not equal\nAlice: %v\nBob  : %v", secretAlice.X, secretBob.X)
	}
	if secretAlice.Y.Cmp(secretBob.Y) != 0 {
		t.Fatalf("key exchange failed - secret Y coordinates not equal\nAlice: %v\nBob  : %v", secretAlice.Y, secretBob.Y)
	}
}

// An example for the ECDH key-exchange using Curve25519.
func TestECDHExampleCurve25519(t *testing.T) {
	curve := new(Curve25519)

	privateAlice, publicAlice, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
	}

	privateBob, publicBob, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate Bob's private/public key pair: %s", err)
	}

	// Alice computes the Diffie-Hellman secret with her private and Bob's
	// public key.
	var secretAlice [32]byte
	curve.ComputeSecret(&secretAlice, privateAlice, publicBob)

	// Bob computes the Diffie-Hellman secret with his private and Alice's
	// public key.
	var secretBob [32]byte
	curve.ComputeSecret(&secretBob, privateBob, publicAlice)

	// Verify if the computes secret are equal
	for i := range secretAlice {
		if secretAlice[i] != secretBob[i] {
			t.Fatalf("key exchange failed - secrets (X coordinates) not equal\nAlice: %v\nBob  : %v", secretAlice, secretBob)
		}
	}
}

func BenchmarkCurve25519(b *testing.B) {
	curve := new(Curve25519)
	privateAlice, _, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
	}
	_, publicBob, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate Bob's private/public key pair: %s", err)
	}
	var secret [32]byte
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		curve.ComputeSecret(&secret, privateAlice, publicBob)
	}
}

func BenchmarkKeyGenerateCurve25519(b *testing.B) {
	curve := new(Curve25519)
	for i := 0; i < b.N; i++ {
		_, _, err := curve.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
		}
	}
}

func BenchmarkP256(b *testing.B) {
	p256 := &Generic{elliptic.P256()}
	privateAlice, _, err := p256.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
	}
	_, publicBob, err := p256.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate Bob's private/public key pair: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p256.ComputeSecret(privateAlice, publicBob)
	}
}

func BenchmarkKeyGenerateP256(b *testing.B) {
	p256 := &Generic{elliptic.P256()}
	for i := 0; i < b.N; i++ {
		_, _, err := p256.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
		}
	}
}

func BenchmarkP521(b *testing.B) {
	p521 := &Generic{elliptic.P521()}
	privateAlice, _, err := p521.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
	}
	_, publicBob, err := p521.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatalf("Failed to generate Bob's private/public key pair: %s", err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p521.ComputeSecret(privateAlice, publicBob)
	}
}

func BenchmarkKeyGenerateP521(b *testing.B) {
	p521 := &Generic{elliptic.P521()}
	for i := 0; i < b.N; i++ {
		_, _, err := p521.GenerateKey(rand.Reader)
		if err != nil {
			b.Fatalf("Failed to generate Alice's private/public key pair: %s", err)
		}
	}
}
