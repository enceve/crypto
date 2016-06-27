// Use of this source code is governed by a license
// that can be found in the LICENSE file

package poly1305

import (
	"encoding/hex"
	"testing"
)

func TestWriteAfterSum(t *testing.T) {
	var sum [TagSize]byte

	msg := make([]byte, 64)
	for i := range msg {
		h := New(new([32]byte))

		if _, err := h.Write(msg[:i]); err != nil {
			t.Fatalf("Iteration %d: poly1305.Hash returned unexpected error: %s", i, err)
		}
		h.Sum(&sum)
		if _, err := h.Write(nil); err == nil {
			t.Fatalf("Iteration %d: poly1305.Hash returned no error for write after sum", i)
		}
	}
}

func TestWrite(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}

	h := New(&key)

	var msg1 []byte
	msg0 := make([]byte, 64)
	for i := range msg0 {
		h.Write(msg0[:i])
		msg1 = append(msg1, msg0[:i]...)
	}

	var tag0, tag1 [TagSize]byte
	h.Sum(&tag0)
	Sum(&tag1, msg1, &key)

	if tag0 != tag1 {
		t.Fatalf("Sum differ from poly1305.Sum\n Sum: %s \n poly1305.Sum: %s", hex.EncodeToString(tag0[:]), hex.EncodeToString(tag1[:]))
	}
}

func TestSum(t *testing.T) {
	var key [32]byte
	for i := range key {
		key[i] = byte(i)
	}

	msg := make([]byte, 64)
	var tag, sum [TagSize]byte
	for i := range msg {
		h := New(&key)
		h.Write(msg[:i])
		h.Sum(&sum)

		Sum(&tag, msg[:i], &key)

		if tag != sum {
			t.Fatalf("Iteration %d: Sum differ from poly1305.Sum\n Sum: %s \n poly1305.Sum %s", i, hex.EncodeToString(sum[:]), hex.EncodeToString(tag[:]))
		}
	}
}

func TestVerify(t *testing.T) {
	for i, v := range vectors {
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to decode key: %s", i, err)
		}
		msg, err := hex.DecodeString(v.msg)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to decode msg: %s", i, err)
		}
		tag, err := hex.DecodeString(v.tag)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to decode tag: %s", i, err)
		}

		var sum [TagSize]byte
		var k [32]byte

		copy(k[:], key)
		copy(sum[:], tag)

		if !Verify(&sum, msg, &k) {
			t.Fatalf("Test vector %d : Poly1305 Verification failed", i)
		}
	}
}

func BenchmarkSum64B(b *testing.B) {
	var key [32]byte
	var tag [16]byte

	msg := make([]byte, 64)
	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(&tag, msg, &key)
	}
}

func BenchmarkSum512B(b *testing.B) {
	var key [32]byte
	var tag [16]byte

	msg := make([]byte, 512)
	b.SetBytes(512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(&tag, msg, &key)
	}
}

func BenchmarkSum1k(b *testing.B) {
	var key [32]byte
	var tag [16]byte

	msg := make([]byte, 1024)
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(&tag, msg, &key)
	}
}

func BenchmarkSum64k(b *testing.B) {
	var key [32]byte
	var tag [16]byte

	msg := make([]byte, 64*1024)
	b.SetBytes(64 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(&tag, msg, &key)
	}
}

func BenchmarkWrite64B(b *testing.B) {
	var key [32]byte
	h := New(&key)
	msg := make([]byte, 64)
	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}

func BenchmarkWrite512B(b *testing.B) {
	var key [32]byte
	h := New(&key)
	msg := make([]byte, 512)
	b.SetBytes(512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}

func BenchmarkWrite1K(b *testing.B) {
	var key [32]byte
	h := New(&key)
	msg := make([]byte, 1024)
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}

func BenchmarkWrite64K(b *testing.B) {
	var key [32]byte
	h := New(&key)
	msg := make([]byte, 64*1024)
	b.SetBytes(64 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}
