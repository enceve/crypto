package blake2b

import "testing"

func TestVerifyParams(t *testing.T) {
	p := new(Params)
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed: %s", err)
	}
	p = &Params{HashSize: 65}
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed: %s", err)
	}
	p = &Params{Key: make([]byte, 64)}
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed: %s", err)
	}
	p = &Params{Key: make([]byte, 64), Salt: make([]byte, 16)}
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed: %s", err)
	}

	p = &Params{Key: make([]byte, 65)}
	if err := verifyParams(p); err == nil {
		t.Fatalf("Verification of invalid parameters passed - Key length: %d", len(p.Key))
	}
	p = &Params{Salt: make([]byte, 17)}
	if err := verifyParams(p); err == nil {
		t.Fatalf("Verification of invalid parameters passed - Salt length: %d", len(p.Salt))
	}
}

// Benchmarks

func BenchmarkWrite(b *testing.B) {
	h, err := New(&Params{})
	if err != nil {
		b.Fatalf("Failed to create blake2b hash: %s", err)
	}
	buf := make([]byte, h.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkSum256(b *testing.B) {
	buf := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum256(buf)
	}
}

func BenchmarkSum512(b *testing.B) {
	buf := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum512(buf)
	}
}
