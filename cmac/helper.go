// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package cmac

const (
	// minimal irreducible polynomial for blocksize
	p64   = 0x1b    // for 64  bit block ciphers
	p128  = 0x87    // for 128 bit block ciphers (like AES)
	p256  = 0x425   // special for large block ciphers (Threefish)
	p512  = 0x125   // special for large block ciphers (Threefish)
	p1024 = 0x80043 // special for large block ciphers (Threefish)
)

func xor(dst, src []byte) {
	for i, v := range src {
		dst[i] ^= v
	}
}

func shift(dst, src []byte) int {
	var b, bit byte
	for i := len(src) - 1; i >= 0; i-- { // a range would be nice
		bit = src[i] >> 7
		dst[i] = src[i]<<1 | b
		b = bit
	}
	return int(b)
}
