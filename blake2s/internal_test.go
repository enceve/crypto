// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package blake2s

import "testing"

func TestVerifyParams(t *testing.T) {
	p := new(Params)
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed: %s", err)
	}
	p = &Params{HashSize: 33}
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed: %s", err)
	}
	p = &Params{Key: make([]byte, 32)}
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed: %s", err)
	}
	p = &Params{Key: make([]byte, 32), Salt: make([]byte, 8)}
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed: %s", err)
	}

	p = &Params{Key: make([]byte, 33)}
	if err := verifyParams(p); err == nil {
		t.Fatalf("Verification of invalid parameters passed - Key length: %d", len(p.Key))
	}
	p = &Params{Salt: make([]byte, 9)}
	if err := verifyParams(p); err == nil {
		t.Fatalf("Verification of invalid parameters passed - Salt length: %d", len(p.Salt))
	}
}

// Benchmarks

func BenchmarkWrite(b *testing.B) {
	h, err := New(&Params{})
	if err != nil {
		b.Fatalf("Failed to create blake2s hash: %s", err)
	}
	buf := make([]byte, h.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkSum160(b *testing.B) {
	buf := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum160(buf)
	}
}

func BenchmarkSum256(b *testing.B) {
	buf := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum256(buf)
	}
}
