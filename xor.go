// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build !amd64

package crypto

// XOR xors the bytes in src and with and writes the result to dst.
// The destination is assumed to have enough space. Returns the
// number of bytes xor'd.
func XOR(dst, src, with []byte) int {
	var a, b []byte
	if len(src) <= len(with) {
		a = src
		b = with
	} else {
		b = src
		a = with
	}

	for i, v := range a {
		dst[i] = b[i] ^ v
	}
	return len(a)
}
