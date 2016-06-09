// Use of this source code is governed by a license
// that can be found in the LICENSE file

package poly1305

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestBlockSize(t *testing.T) {
	h, err := New(make([]byte, 32))
	if err != nil {
		t.Fatalf("Could not create Poly1305 instance: %s", err)
	}
	if bs := h.BlockSize(); bs != TagSize {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, TagSize)
	}
}

func TestSize(t *testing.T) {
	h, err := New(make([]byte, 32))
	if err != nil {
		t.Fatalf("Could not create Poly1305 instance: %s", err)
	}
	if s := h.Size(); s != TagSize {
		t.Fatalf("Size() returned: %d - but expected: %d", s, TagSize)
	}
}

func TestReset(t *testing.T) {
	h, err := New(make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create instance of Poly1305: %s", err)
	} else {
		defer func() {
			if err := recover(); err == nil {
				t.Fatal("Poly1305 allowed Reset(), but Poly1305 is a one-time key scheme")
			}
		}()
		h.Reset()
	}
}

func TestWrite(t *testing.T) {
	h, err := New(make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create instance of Poly1305: %s", err)
	}
	n, err := h.Write(nil)
	if n != 0 || err != nil {
		t.Fatalf("Failed to process nil slice: Processed bytes: %d - Returned error: %s", n, err)
	}
	n, err = h.Write(make([]byte, h.Size()))
	if n != h.Size() || err != nil {
		t.Fatalf("Failed to process 0-slice with length %d: Processed bytes: %d - Returned error: %s", h.Size(), n, err)
	}
	n, err = h.Write(make([]byte, h.BlockSize()))
	if n != h.BlockSize() || err != nil {
		t.Fatalf("Failed to process 0-slice with length %d: Processed bytes: %d - Returned error: %s", h.BlockSize(), n, err)
	}
	n, err = h.Write(make([]byte, 211)) // 211 = (2*3*5*7)+1 is prime
	if n != 211 || err != nil {
		t.Fatalf("Failed to process 0-slice with length %d: Processed bytes: %d - Returned error: %s", 211, n, err)
	}
}

func TestSum(t *testing.T) {
	h, err := New(make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create Poly130 instance: %s", err)
	}
	var one = [1]byte{1}

	h.Sum(nil)
	h.Write(make([]byte, TagSize))
	h.Write(one[:])

	sum1 := h.Sum(nil)

	var key [32]byte
	var sum2 [16]byte
	Sum(&sum2, append(make([]byte, TagSize), one[:]...), &key)

	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

func TestNew(t *testing.T) {
	_, err := New(make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create Poly1305 instance: %s", err)
	}

	_, err = New(nil)
	if err == nil {
		t.Fatal("Accepted invalid nil argument for key")
	}

	_, err = New(make([]byte, TagSize))
	if err == nil {
		t.Fatalf("Accepted invalid key argument with len: %d", TagSize)
	}

	_, err = New(make([]byte, 33))
	if err == nil {
		t.Fatalf("Accepted invalid key argument with len: %d", 33)
	}
}

func TestSumFunc(t *testing.T) {
	h, err := New(make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create Poly1305 instance: %s", err)
	}
	var key [32]byte

	h.Write(nil)
	sum1 := h.Sum(nil)
	var sum2 [TagSize]byte
	Sum(&sum2, nil, &key)
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}

	h, err = New(make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create Poly1305 instance: %s", err)
	}

	h.Write(make([]byte, 1))
	sum1 = h.Sum(nil)
	Sum(&sum2, make([]byte, 1), &key)
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
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

func BenchmarkSum256B(b *testing.B) {
	var key [32]byte
	var tag [16]byte

	msg := make([]byte, 256)
	b.SetBytes(256)
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

func BenchmarkSum16k(b *testing.B) {
	var key [32]byte
	var tag [16]byte

	msg := make([]byte, 16*1024)
	b.SetBytes(16 * 1024)
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
	h, err := New(make([]byte, 32))
	if err != nil {
		b.Fatalf("Failed to create poly1305 instance: %s", err)
	}
	msg := make([]byte, 64)
	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}

func BenchmarkWrite256B(b *testing.B) {
	h, err := New(make([]byte, 32))
	if err != nil {
		b.Fatalf("Failed to create poly1305 instance: %s", err)
	}
	msg := make([]byte, 256)
	b.SetBytes(256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}

func BenchmarkWrite512B(b *testing.B) {
	h, err := New(make([]byte, 32))
	if err != nil {
		b.Fatalf("Failed to create poly1305 instance: %s", err)
	}
	msg := make([]byte, 512)
	b.SetBytes(512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}

func BenchmarkWrite1K(b *testing.B) {
	h, err := New(make([]byte, 32))
	if err != nil {
		b.Fatalf("Failed to create poly1305 instance: %s", err)
	}
	msg := make([]byte, 1024)
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}

func BenchmarkWrite16K(b *testing.B) {
	h, err := New(make([]byte, 32))
	if err != nil {
		b.Fatalf("Failed to create poly1305 instance: %s", err)
	}
	msg := make([]byte, 16*1024)
	b.SetBytes(16 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}

func BenchmarkWrite64K(b *testing.B) {
	h, err := New(make([]byte, 32))
	if err != nil {
		b.Fatalf("Failed to create poly1305 instance: %s", err)
	}
	msg := make([]byte, 64*1024)
	b.SetBytes(64 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}
