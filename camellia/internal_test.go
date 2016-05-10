// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package camellia

import "testing"

// Benchmarks

func BenchmarkEncrypt128(b *testing.B) {
	c, err := New(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create Camellia instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkEncrypt256(b *testing.B) {
	c, err := New(make([]byte, 32))
	if err != nil {
		b.Fatalf("Failed to create Camellia instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Encrypt(buf, buf)
	}
}

func BenchmarkDecrypt128(b *testing.B) {
	c, err := New(make([]byte, 16))
	if err != nil {
		b.Fatalf("Failed to create Camellia instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(buf, buf)
	}
}

func BenchmarkDecrypt256(b *testing.B) {
	c, err := New(make([]byte, 32))
	if err != nil {
		b.Fatalf("Failed to create Camellia instance: %s", err)
	}
	buf := make([]byte, c.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Decrypt(buf, buf)
	}
}

func BenchmarkKeySchedule128(b *testing.B) {
	c := new(camellia128)
	key := make([]byte, 16)
	for i := 0; i < b.N; i++ {
		c.keySchedule(key)
	}
}

func BenchmarkKeySchedule256(b *testing.B) {
	c := new(camellia)
	key := make([]byte, 32)
	for i := 0; i < b.N; i++ {
		c.keySchedule(key)
	}
}
