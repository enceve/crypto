// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package dh

import (
	"crypto/rand"
	"fmt"
	"testing"
)

// A Diffie-Hellman exchange example.
func ExampleKeyExchange() {
	// using 2048 bit group
	group := RFC3526_2048()

	// Alice
	alicePrivate, alicePublic, err := group.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate alice's private / public key pair: %s", err)
	}

	// Bob
	bobPrivate, bobPublic, err := group.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Printf("Failed to generate bob's private / public key pair: %s", err)
	}

	secretAlice := group.ComputeSecret(alicePrivate, bobPublic)
	secretBob := group.ComputeSecret(bobPrivate, alicePublic)

	if secretAlice.Cmp(secretBob) != 0 {
		fmt.Printf("key exchange failed - secrets not equal\nAlice: %v\nBob  : %v", secretAlice, secretBob)
	}

	fmt.Println("key exchange succeed")
	// Output:
	// key exchange succeed
}

func BenchmarkGenerateKey2048(b *testing.B) {
	group := RFC3526_2048()
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
	for i := 0; i < b.N; i++ {
		group.ComputeSecret(alicePrivate, bobPublic)
	}
}
