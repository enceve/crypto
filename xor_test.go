package crypto

import (
	"bytes"
	"encoding/hex"
	"testing"
	"unsafe"
)

func unalignBytes(in []byte) []byte {
	out := make([]byte, len(in)+1)
	if uintptr(unsafe.Pointer(&out[0]))&(unsafe.Alignof(uint32(0))-1) == 0 {
		out = out[1:]
	} else {
		out = out[:len(in)]
	}
	copy(out, in)
	return out
}

func testXOR(t *testing.T, dSize, sSize, wSize int, unalign bool) {
	dst0, src, with := make([]byte, dSize), make([]byte, sSize), make([]byte, wSize)
	dst1 := make([]byte, dSize)

	if unalign {
		with = unalignBytes(with)
	}

	var n int
	if len(src) < len(with) {
		n = len(src)
	} else {
		n = len(with)
	}

	for i := 0; i < n; i++ {
		src[i] = byte(i)
		with[i] = byte(i + 1)
		dst0[i] = src[i] ^ with[i]
	}
	XOR(dst1, src, with)

	if !bytes.Equal(dst0, dst1) {
		t.Fatalf("xor failed:\nexpected: %s\ngot: %s", hex.EncodeToString(dst0), hex.EncodeToString(dst1))
	}
}

func TestXOR(t *testing.T) {
	testXOR(t, 0, 0, 0, true)
	testXOR(t, 0, 0, 0, false)
	testXOR(t, 64, 64, 64, true)
	testXOR(t, 64, 64, 64, false)
	testXOR(t, 65, 64, 63, true)
	testXOR(t, 65, 64, 63, false)
	testXOR(t, 16, 16, 64, true)
	testXOR(t, 16, 16, 64, false)
}

func benchmarkXOR(b *testing.B, size int, unalign bool) {
	dst, src, with := make([]byte, size), make([]byte, size), make([]byte, size)
	if unalign {
		with = unalignBytes(with)
	}

	b.SetBytes(int64(size))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		XOR(dst, src, with)
	}
}

func BenchmarkXOR_64(b *testing.B)          { benchmarkXOR(b, 64, false) }
func BenchmarkXOR_1K(b *testing.B)          { benchmarkXOR(b, 1024, false) }
func BenchmarkXORUnaligned_64(b *testing.B) { benchmarkXOR(b, 64, true) }
func BenchmarkXORUnaligned_1K(b *testing.B) { benchmarkXOR(b, 1024, true) }
