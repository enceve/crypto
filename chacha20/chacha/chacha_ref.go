// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build !amd64

package chacha

// XORKeyStream crypts bytes from src to dst using the given key, nonce and counter.
// The rounds argument specifies the number of rounds performed for keystream generation.
// (Common values are 20, 12 or 8) Src and dst may be the same slice but otherwise should
// not overlap. If len(dst) < len(src) the behavior is undefined.
func XORKeyStream(dst, src []byte, nonce *[12]byte, key *[32]byte, counter uint32, rounds int) {
	var state [16]uint32

	state[0] = constants[0]
	state[1] = constants[1]
	state[2] = constants[2]
	state[3] = constants[3]

	state[4] = uint32(key[0]) | uint32(key[1])<<8 | uint32(key[2])<<16 | uint32(key[3])<<24
	state[5] = uint32(key[4]) | uint32(key[5])<<8 | uint32(key[6])<<16 | uint32(key[7])<<24
	state[6] = uint32(key[8]) | uint32(key[9])<<8 | uint32(key[10])<<16 | uint32(key[11])<<24
	state[7] = uint32(key[12]) | uint32(key[13])<<8 | uint32(key[14])<<16 | uint32(key[15])<<24
	state[8] = uint32(key[16]) | uint32(key[17])<<8 | uint32(key[18])<<16 | uint32(key[19])<<24
	state[9] = uint32(key[20]) | uint32(key[21])<<8 | uint32(key[22])<<16 | uint32(key[23])<<24
	state[10] = uint32(key[24]) | uint32(key[25])<<8 | uint32(key[26])<<16 | uint32(key[27])<<24
	state[11] = uint32(key[28]) | uint32(key[29])<<8 | uint32(key[30])<<16 | uint32(key[31])<<24

	state[12] = counter

	state[13] = uint32(nonce[0]) | uint32(nonce[1])<<8 | uint32(nonce[2])<<16 | uint32(nonce[3])<<24
	state[14] = uint32(nonce[4]) | uint32(nonce[5])<<8 | uint32(nonce[6])<<16 | uint32(nonce[7])<<24
	state[15] = uint32(nonce[8]) | uint32(nonce[9])<<8 | uint32(nonce[10])<<16 | uint32(nonce[11])<<24

	length := len(src)
	n := length - (length % 64)
	if n > 0 {
		XORBlocks(dst, src, &state, rounds)
	}

	length -= n
	if length > 0 {
		src = src[n:]
		dst = dst[n:]

		var block [64]byte
		Core(&block, &state, rounds)

		for i, v := range src {
			dst[i] = v ^ block[i]
		}
	}
}

// NewCipher returns a new *chacha.Cipher implementing the ChaCha/X (X = rounds)
// stream cipher. The nonce must be unique for one
// key for all time.
func NewCipher(nonce *[12]byte, key *[32]byte, rounds int) *Cipher {
	if rounds%2 != 0 {
		panic("rounds must be a multiply of 2")
	}
	c := new(Cipher)
	c.rounds = rounds

	c.state[0] = constants[0]
	c.state[1] = constants[1]
	c.state[2] = constants[2]
	c.state[3] = constants[3]

	c.state[4] = uint32(key[0]) | uint32(key[1])<<8 | uint32(key[2])<<16 | uint32(key[3])<<24
	c.state[5] = uint32(key[4]) | uint32(key[5])<<8 | uint32(key[6])<<16 | uint32(key[7])<<24
	c.state[6] = uint32(key[8]) | uint32(key[9])<<8 | uint32(key[10])<<16 | uint32(key[11])<<24
	c.state[7] = uint32(key[12]) | uint32(key[13])<<8 | uint32(key[14])<<16 | uint32(key[15])<<24
	c.state[8] = uint32(key[16]) | uint32(key[17])<<8 | uint32(key[18])<<16 | uint32(key[19])<<24
	c.state[9] = uint32(key[20]) | uint32(key[21])<<8 | uint32(key[22])<<16 | uint32(key[23])<<24
	c.state[10] = uint32(key[24]) | uint32(key[25])<<8 | uint32(key[26])<<16 | uint32(key[27])<<24
	c.state[11] = uint32(key[28]) | uint32(key[29])<<8 | uint32(key[30])<<16 | uint32(key[31])<<24

	c.state[12] = 0

	c.state[13] = uint32(nonce[0]) | uint32(nonce[1])<<8 | uint32(nonce[2])<<16 | uint32(nonce[3])<<24
	c.state[14] = uint32(nonce[4]) | uint32(nonce[5])<<8 | uint32(nonce[6])<<16 | uint32(nonce[7])<<24
	c.state[15] = uint32(nonce[8]) | uint32(nonce[9])<<8 | uint32(nonce[10])<<16 | uint32(nonce[11])<<24

	return c
}

// XORKeyStream crypts bytes from src to dst. Src and dst may be the same slice
// but otherwise should not overlap. If len(dst) < len(src) the function panics.
func (c *Cipher) XORKeyStream(dst, src []byte) {
	length := len(src)
	if len(dst) < length {
		panic("dst buffer is to small")
	}

	if c.off > 0 {
		left := 64 - c.off
		if left > length {
			left = length
		}
		for i, v := range c.block[c.off : c.off+left] {
			dst[i] = src[i] ^ v
		}
		src = src[left:]
		dst = dst[left:]
		length -= left
		c.off += left
		if c.off == 64 {
			c.off = 0
		}
	}

	n := length - (length % 64)
	XORBlocks(dst, src, &(c.state), c.rounds)

	length -= n
	if length > 0 {
		src = src[n:]
		dst = dst[n:]

		Core(&(c.block), &(c.state), c.rounds)
		c.state[12]++

		for i, v := range src {
			dst[i] = v ^ c.block[i]
		}
		c.off += length
	}
}

// XORBlocks crypts full block ( len(src) - (len(src) mod 64) bytes ) from src to
// dst using the state. Src and dst may be the same slice
// but otherwise should not overlap. If len(dst) < len(src) the behavior is undefined.
// This function increments the counter.
func XORBlocks(dst, src []byte, state *[16]uint32, rounds int) {
	length := len(src)
	n := length - (length % 64)

	var block [64]byte
	for i := 0; i < n; i += 64 {
		Core(&block, state, rounds)
		state[12]++

		j := i
		for _, v := range block {
			dst[j] = src[j] ^ v
			j++
		}
	}
}

// Core generates 64 byte keystream from the given state performing 'rounds' rounds
// and writes them to dst. This function expects valid values. (no nil ptr etc.)
// Core does NOT increment the counter.
func Core(dst *[64]byte, state *[16]uint32, rounds int) {
	v00, v01, v02, v03 := state[0], state[1], state[2], state[3]
	v04, v05, v06, v07 := state[4], state[5], state[6], state[7]
	v08, v09, v10, v11 := state[8], state[9], state[10], state[11]
	v12, v13, v14, v15 := state[12], state[13], state[14], state[15]

	for i := 0; i < rounds; i += 2 {
		v00 += v04
		v12 ^= v00
		v12 = (v12 << 16) | (v12 >> (16))
		v08 += v12
		v04 ^= v08
		v04 = (v04 << 12) | (v04 >> (20))
		v00 += v04
		v12 ^= v00
		v12 = (v12 << 8) | (v12 >> (24))
		v08 += v12
		v04 ^= v08
		v04 = (v04 << 7) | (v04 >> (25))
		v01 += v05
		v13 ^= v01
		v13 = (v13 << 16) | (v13 >> 16)
		v09 += v13
		v05 ^= v09
		v05 = (v05 << 12) | (v05 >> 20)
		v01 += v05
		v13 ^= v01
		v13 = (v13 << 8) | (v13 >> 24)
		v09 += v13
		v05 ^= v09
		v05 = (v05 << 7) | (v05 >> 25)
		v02 += v06
		v14 ^= v02
		v14 = (v14 << 16) | (v14 >> 16)
		v10 += v14
		v06 ^= v10
		v06 = (v06 << 12) | (v06 >> 20)
		v02 += v06
		v14 ^= v02
		v14 = (v14 << 8) | (v14 >> 24)
		v10 += v14
		v06 ^= v10
		v06 = (v06 << 7) | (v06 >> 25)
		v03 += v07
		v15 ^= v03
		v15 = (v15 << 16) | (v15 >> 16)
		v11 += v15
		v07 ^= v11
		v07 = (v07 << 12) | (v07 >> 20)
		v03 += v07
		v15 ^= v03
		v15 = (v15 << 8) | (v15 >> 24)
		v11 += v15
		v07 ^= v11
		v07 = (v07 << 7) | (v07 >> 25)
		v00 += v05
		v15 ^= v00
		v15 = (v15 << 16) | (v15 >> 16)
		v10 += v15
		v05 ^= v10
		v05 = (v05 << 12) | (v05 >> 20)
		v00 += v05
		v15 ^= v00
		v15 = (v15 << 8) | (v15 >> 24)
		v10 += v15
		v05 ^= v10
		v05 = (v05 << 7) | (v05 >> 25)
		v01 += v06
		v12 ^= v01
		v12 = (v12 << 16) | (v12 >> 16)
		v11 += v12
		v06 ^= v11
		v06 = (v06 << 12) | (v06 >> 20)
		v01 += v06
		v12 ^= v01
		v12 = (v12 << 8) | (v12 >> 24)
		v11 += v12
		v06 ^= v11
		v06 = (v06 << 7) | (v06 >> 25)
		v02 += v07
		v13 ^= v02
		v13 = (v13 << 16) | (v13 >> 16)
		v08 += v13
		v07 ^= v08
		v07 = (v07 << 12) | (v07 >> 20)
		v02 += v07
		v13 ^= v02
		v13 = (v13 << 8) | (v13 >> 24)
		v08 += v13
		v07 ^= v08
		v07 = (v07 << 7) | (v07 >> 25)
		v03 += v04
		v14 ^= v03
		v14 = (v14 << 16) | (v14 >> 16)
		v09 += v14
		v04 ^= v09
		v04 = (v04 << 12) | (v04 >> 20)
		v03 += v04
		v14 ^= v03
		v14 = (v14 << 8) | (v14 >> 24)
		v09 += v14
		v04 ^= v09
		v04 = (v04 << 7) | (v04 >> 25)
	}

	v00 += state[0]
	v01 += state[1]
	v02 += state[2]
	v03 += state[3]
	v04 += state[4]
	v05 += state[5]
	v06 += state[6]
	v07 += state[7]
	v08 += state[8]
	v09 += state[9]
	v10 += state[10]
	v11 += state[11]
	v12 += state[12]
	v13 += state[13]
	v14 += state[14]
	v15 += state[15]

	dst[0] = byte(v00)
	dst[1] = byte(v00 >> 8)
	dst[2] = byte(v00 >> 16)
	dst[3] = byte(v00 >> 24)

	dst[4] = byte(v01)
	dst[5] = byte(v01 >> 8)
	dst[6] = byte(v01 >> 16)
	dst[7] = byte(v01 >> 24)

	dst[8] = byte(v02)
	dst[9] = byte(v02 >> 8)
	dst[10] = byte(v02 >> 16)
	dst[11] = byte(v02 >> 24)

	dst[12] = byte(v03)
	dst[13] = byte(v03 >> 8)
	dst[14] = byte(v03 >> 16)
	dst[15] = byte(v03 >> 24)

	dst[16] = byte(v04)
	dst[17] = byte(v04 >> 8)
	dst[18] = byte(v04 >> 16)
	dst[19] = byte(v04 >> 24)

	dst[20] = byte(v05)
	dst[21] = byte(v05 >> 8)
	dst[22] = byte(v05 >> 16)
	dst[23] = byte(v05 >> 24)

	dst[24] = byte(v06)
	dst[25] = byte(v06 >> 8)
	dst[26] = byte(v06 >> 16)
	dst[27] = byte(v06 >> 24)

	dst[28] = byte(v07)
	dst[29] = byte(v07 >> 8)
	dst[30] = byte(v07 >> 16)
	dst[31] = byte(v07 >> 24)

	dst[32] = byte(v08)
	dst[33] = byte(v08 >> 8)
	dst[34] = byte(v08 >> 16)
	dst[35] = byte(v08 >> 24)

	dst[36] = byte(v09)
	dst[37] = byte(v09 >> 8)
	dst[38] = byte(v09 >> 16)
	dst[39] = byte(v09 >> 24)

	dst[40] = byte(v10)
	dst[41] = byte(v10 >> 8)
	dst[42] = byte(v10 >> 16)
	dst[43] = byte(v10 >> 24)

	dst[44] = byte(v11)
	dst[45] = byte(v11 >> 8)
	dst[46] = byte(v11 >> 16)
	dst[47] = byte(v11 >> 24)

	dst[48] = byte(v12)
	dst[49] = byte(v12 >> 8)
	dst[50] = byte(v12 >> 16)
	dst[51] = byte(v12 >> 24)

	dst[52] = byte(v13)
	dst[53] = byte(v13 >> 8)
	dst[54] = byte(v13 >> 16)
	dst[55] = byte(v13 >> 24)

	dst[56] = byte(v14)
	dst[57] = byte(v14 >> 8)
	dst[58] = byte(v14 >> 16)
	dst[59] = byte(v14 >> 24)

	dst[60] = byte(v15)
	dst[61] = byte(v15 >> 8)
	dst[62] = byte(v15 >> 16)
	dst[63] = byte(v15 >> 24)
}
