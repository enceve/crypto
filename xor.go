package crypto

import (
	"runtime"
	"unsafe"
)

const wordSize = int(unsafe.Sizeof(uintptr(0)))
const supportsUnaligned = runtime.GOARCH == "386" || runtime.GOARCH == "amd64"

// fastXORBytes xors in bulk. It only works on architectures that
// support unaligned read/writes.
func fastXORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}

	w := n / wordSize
	if w > 0 {
		dw := *(*[]uintptr)(unsafe.Pointer(&dst))
		aw := *(*[]uintptr)(unsafe.Pointer(&a))
		bw := *(*[]uintptr)(unsafe.Pointer(&b))
		for i := 0; i < w; i++ {
			dw[i] = aw[i] ^ bw[i]
		}
	}

	for i := (n - n%wordSize); i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}

	return n
}

func safeXORBytes(dst, a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i, v := range a[:n] {
		dst[i] = v ^ b[i]
	}
	return n
}

// xorBytes xors the bytes in src and with. The destination is assumed to have enough
// space. Returns the number of bytes xor'd.
func xorBytes(dst, src, with []byte) int {
	if supportsUnaligned {
		return fastXORBytes(dst, src, with)
	} else {
		return safeXORBytes(dst, src, with)
	}
}

// fastXORWords XORs multiples of 4 or 8 bytes (depending on architecture.)
// The arguments are assumed to be of equal length.
func fastXORWords(dst, a, b []byte, n int) {
	dw := *(*[]uintptr)(unsafe.Pointer(&dst))
	aw := *(*[]uintptr)(unsafe.Pointer(&a))
	bw := *(*[]uintptr)(unsafe.Pointer(&b))
	for i := 0; i < n; i++ {
		dw[i] = aw[i] ^ bw[i]
	}
}

// XOR xors the bytes in src and with. The destination is assumed to have enough
// space. Returns the number of bytes xor'd.
func XOR(dst, src, with []byte) int {
	sLen := len(src)
	if sLen%wordSize != 0 {
		return xorBytes(dst, src, with)
	}
	wLen := len(with)
	if wLen%wordSize != 0 {
		return xorBytes(dst, src, with)
	}

	var n int
	if sLen < wLen {
		n = sLen
	} else {
		n = wLen
	}

	if len(dst) < n {
		panic("dst is to small")
	}

	if supportsUnaligned {
		fastXORWords(dst, src, with, n/wordSize)
	} else {
		safeXORBytes(dst, src, with)
	}
	return n
}
