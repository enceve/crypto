// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build amd64, !cgo, !appengine

package crypto

import "unsafe"

const wordSize = int(unsafe.Sizeof(uintptr(0)))

// XOR xors the bytes in src and with and writes the result to dst.
// The destination is assumed to have enough space. Returns the
// number of bytes xor'd.
func XOR(dst, src, with []byte) int {
	n := len(src)
	if len(with) < n {
		n = len(with)
	}

	w := n / wordSize
	if w > 0 {
		dstPtr := *(*[]uintptr)(unsafe.Pointer(&dst))
		srcPtr := *(*[]uintptr)(unsafe.Pointer(&src))
		withPtr := *(*[]uintptr)(unsafe.Pointer(&with))
		for i, v := range srcPtr[:w] {
			dstPtr[i] = withPtr[i] ^ v
		}
	}

	for i := (n & (^(wordSize - 1))); i < n; i++ {
		dst[i] = src[i] ^ with[i]
	}

	return n
}
