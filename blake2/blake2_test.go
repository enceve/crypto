// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package blake2

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/enceve/crypto/blake2/blake2b"
	"github.com/enceve/crypto/blake2/blake2s"
)

var msgLens = [8]int{0, 63, 64, 65, 127, 128, 129, 1024}
var keyLens = [8]int{0, 16, 24, 32}

func generateSequence(out []byte, seed uint32) {
	a := 0xDEAD4BAD * seed
	b := uint32(1)

	for i := range out {
		t := a + b
		a = b
		b = t
		out[i] = byte(t >> 24)
	}
}

func TestSum512(t *testing.T) {
	var sum [64]byte
	msg := make([]byte, 1024)
	key := make([]byte, 64)

	for _, kl := range keyLens {
		for _, ml := range msgLens {
			m := msg[:ml]

			generateSequence(m, uint32(kl+ml))
			expected, err := blake2b.Sum(m, 64, nil)
			if err != nil {
				t.Fatalf("Failed to compute BLAKE2b sum: %s", err)
			}
			Sum512(&sum, m, nil)
			if !bytes.Equal(sum[:], expected) {
				t.Fatalf("Unkeyed hash values not equal\nFound: %s\nExpected: %s", hex.EncodeToString(sum[:]), hex.EncodeToString(expected))
			}

			k := key[:kl]
			generateSequence(k, uint32(ml))
			expected, err = blake2b.Sum(m, 64, &blake2b.Config{Key: k})
			if err != nil {
				t.Fatalf("Keyed hash values not equal\nFound: %s\nExpected: %s", hex.EncodeToString(sum[:]), hex.EncodeToString(expected))
			}
			Sum512(&sum, m, k)
			if !bytes.Equal(sum[:], expected) {
				t.Fatalf("")
			}
		}
	}
}

func TestSum256b(t *testing.T) {
	var sum [32]byte
	msg := make([]byte, 1024)
	key := make([]byte, 64)

	for _, kl := range keyLens {
		for _, ml := range msgLens {
			m := msg[:ml]

			generateSequence(m, uint32(kl+ml))
			expected, err := blake2b.Sum(m, 32, nil)
			if err != nil {
				t.Fatalf("Failed to compute BLAKE2b sum: %s", err)
			}
			Sum256b(&sum, m, nil)
			if !bytes.Equal(sum[:], expected) {
				t.Fatalf("Unkeyed hash values not equal\nFound: %s\nExpected: %s", hex.EncodeToString(sum[:]), hex.EncodeToString(expected))
			}

			k := key[:kl]
			generateSequence(k, uint32(ml))
			expected, err = blake2b.Sum(m, 32, &blake2b.Config{Key: k})
			if err != nil {
				t.Fatalf("Keyed hash values not equal\nFound: %s\nExpected: %s", hex.EncodeToString(sum[:]), hex.EncodeToString(expected))
			}
			Sum256b(&sum, m, k)
			if !bytes.Equal(sum[:], expected) {
				t.Fatalf("")
			}
		}
	}
}

func TestSum256s(t *testing.T) {
	var sum [32]byte
	msg := make([]byte, 1024)
	key := make([]byte, 64)

	for _, kl := range keyLens {
		for _, ml := range msgLens {
			m := msg[:ml]

			generateSequence(m, uint32(kl+ml))
			expected, err := blake2s.Sum(m, 32, nil)
			if err != nil {
				t.Fatalf("Failed to compute BLAKE2b sum: %s", err)
			}
			Sum256s(&sum, m, nil)
			if !bytes.Equal(sum[:], expected) {
				t.Fatalf("Unkeyed hash values not equal\nFound: %s\nExpected: %s", hex.EncodeToString(sum[:]), hex.EncodeToString(expected))
			}

			k := key[:kl]
			generateSequence(k, uint32(ml))
			expected, err = blake2s.Sum(m, 32, &blake2s.Config{Key: k})
			if err != nil {
				t.Fatalf("Keyed hash values not equal\nFound: %s\nExpected: %s", hex.EncodeToString(sum[:]), hex.EncodeToString(expected))
			}
			Sum256s(&sum, m, k)
			if !bytes.Equal(sum[:], expected) {
				t.Fatalf("")
			}
		}
	}
}

func TestSum160s(t *testing.T) {
	var sum [20]byte
	msg := make([]byte, 1024)
	key := make([]byte, 64)

	for _, kl := range keyLens {
		for _, ml := range msgLens {
			m := msg[:ml]

			generateSequence(m, uint32(kl+ml))
			expected, err := blake2s.Sum(m, 20, nil)
			if err != nil {
				t.Fatalf("Failed to compute BLAKE2b sum: %s", err)
			}
			Sum160s(&sum, m, nil)
			if !bytes.Equal(sum[:], expected) {
				t.Fatalf("Unkeyed hash values not equal\nFound: %s\nExpected: %s", hex.EncodeToString(sum[:]), hex.EncodeToString(expected))
			}

			k := key[:kl]
			generateSequence(k, uint32(ml))
			expected, err = blake2s.Sum(m, 20, &blake2s.Config{Key: k})
			if err != nil {
				t.Fatalf("Keyed hash values not equal\nFound: %s\nExpected: %s", hex.EncodeToString(sum[:]), hex.EncodeToString(expected))
			}
			Sum160s(&sum, m, k)
			if !bytes.Equal(sum[:], expected) {
				t.Fatalf("")
			}
		}
	}
}

// Benchmarks

func benchmarkSum512(b *testing.B, size int) {
	var sum512 [64]byte
	buf := make([]byte, size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum512(&sum512, buf, nil)
	}
}

func benchmarkSum256s(b *testing.B, size int) {
	var sum256s [32]byte
	buf := make([]byte, size)
	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum256s(&sum256s, buf, nil)
	}
}

func BenchmarkSum512_64(b *testing.B)    { benchmarkSum512(b, 64) }
func BenchmarkSum512_1024(b *testing.B)  { benchmarkSum512(b, 1024) }
func BenchmarkSum256s_64(b *testing.B)   { benchmarkSum256s(b, 64) }
func BenchmarkSum256s_1024(b *testing.B) { benchmarkSum256s(b, 1024) }
