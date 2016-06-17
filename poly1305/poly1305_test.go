// Use of this source code is governed by a license
// that can be found in the LICENSE file

package poly1305

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestWrite(t *testing.T) {
	var key [32]byte
	var sum [TagSize]byte
	h := New(&key)

	_, err := h.Write(make([]byte, TagSize))
	if err != nil {
		t.Fatalf("Hash returns an unexpected error: %s", err)
	}
	h.Sum(&sum)
	_, err = h.Write(make([]byte, TagSize))
	if err == nil {
		t.Fatalf("Hash returns no error, but write-after-sum error ecpected")
	}
}

func TestSum(t *testing.T) {
	var key [32]byte
	var sum, sum2 [TagSize]byte
	h := New(&key)

	_, err := h.Write(make([]byte, TagSize))
	if err != nil {
		t.Fatalf("Hash returns an unexpected error: %s", err)
	}
	h.Sum(&sum)
	h.Sum(&sum2)
	if !bytes.Equal(sum[:], sum2[:]) {
		t.Fatalf("first sum is not equal to second sum: %s : %s", hex.EncodeToString(sum[:]), hex.EncodeToString(sum2[:]))
	}
}

func TestSumFunc(t *testing.T) {
	var key [32]byte
	var sum, sum2 [TagSize]byte

	h := New(&key)
	h.Write(nil)
	h.Sum(&sum)

	Sum(&sum2, nil, &key)
	if !bytes.Equal(sum[:], sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum[:]), hex.EncodeToString(sum2[:]))
	}

	h = New(&key)
	h.Write(make([]byte, 1))
	h.Sum(&sum)

	Sum(&sum2, make([]byte, 1), &key)
	if !bytes.Equal(sum[:], sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum[:]), hex.EncodeToString(sum2[:]))
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
