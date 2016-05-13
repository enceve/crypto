// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package chacha

// The chacha core function for updating
// the state and extract the keystream.
func chachaCore(dst *[64]byte, state *[16]uint32, rounds int) {
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
