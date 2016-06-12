// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package blake2s

func Core(hVal *[8]uint32, counter *[2]uint32, flag uint32, msg []byte) {
	h0, h1, h2, h3 := hVal[0], hVal[1], hVal[2], hVal[3]
	h4, h5, h6, h7 := hVal[4], hVal[5], hVal[6], hVal[7]
	ctr0 := counter[0]
	ctr1 := counter[1]

	var m [16]uint32

	length := len(msg)
	for i := 0; i < length; i += BlockSize {
		ctr0 += BlockSize
		if ctr0 < BlockSize {
			ctr1++
		}

		v0, v1, v2, v3, v4, v5, v6, v7 := h0, h1, h2, h3, h4, h5, h6, h7
		v8, v9, v10, v11 := iv[0], iv[1], iv[2], iv[3]
		v12, v13, v14, v15 := iv[4], iv[5], iv[6], iv[7]
		v12 ^= ctr0
		v13 ^= ctr1
		v14 ^= flag

		j := i
		for k := range m {
			m[k] = uint32(msg[j]) | uint32(msg[j+1])<<8 | uint32(msg[j+2])<<16 | uint32(msg[j+3])<<24
			j += 4
		}

		for k := range precomputed {
			s := &(precomputed[k])

			v0 += m[s[0]]
			v0 += v4
			v12 ^= v0
			v12 = v12<<(32-16) | v12>>16
			v8 += v12
			v4 ^= v8
			v4 = v4<<(32-12) | v4>>12
			v1 += m[s[1]]
			v1 += v5
			v13 ^= v1
			v13 = v13<<(32-16) | v13>>16
			v9 += v13
			v5 ^= v9
			v5 = v5<<(32-12) | v5>>12
			v2 += m[s[2]]
			v2 += v6
			v14 ^= v2
			v14 = v14<<(32-16) | v14>>16
			v10 += v14
			v6 ^= v10
			v6 = v6<<(32-12) | v6>>12
			v3 += m[s[3]]
			v3 += v7
			v15 ^= v3
			v15 = v15<<(32-16) | v15>>16
			v11 += v15
			v7 ^= v11
			v7 = v7<<(32-12) | v7>>12

			v0 += m[s[7]]
			v0 += v4
			v12 ^= v0
			v12 = v12<<(32-8) | v12>>8
			v8 += v12
			v4 ^= v8
			v4 = v4<<(32-7) | v4>>7
			v1 += m[s[6]]
			v1 += v5
			v13 ^= v1
			v13 = v13<<(32-8) | v13>>8
			v9 += v13
			v5 ^= v9
			v5 = v5<<(32-7) | v5>>7
			v2 += m[s[4]]
			v2 += v6
			v14 ^= v2
			v14 = v14<<(32-8) | v14>>8
			v10 += v14
			v6 ^= v10
			v6 = v6<<(32-7) | v6>>7
			v3 += m[s[5]]
			v3 += v7
			v15 ^= v3
			v15 = v15<<(32-8) | v15>>8
			v11 += v15
			v7 ^= v11
			v7 = v7<<(32-7) | v7>>7

			v0 += m[s[8]]
			v0 += v5
			v15 ^= v0
			v15 = v15<<(32-16) | v15>>16
			v10 += v15
			v5 ^= v10
			v5 = v5<<(32-12) | v5>>12
			v1 += m[s[9]]
			v1 += v6
			v12 ^= v1
			v12 = v12<<(32-16) | v12>>16
			v11 += v12
			v6 ^= v11
			v6 = v6<<(32-12) | v6>>12
			v2 += m[s[10]]
			v2 += v7
			v13 ^= v2
			v13 = v13<<(32-16) | v13>>16
			v8 += v13
			v7 ^= v8
			v7 = v7<<(32-12) | v7>>12
			v3 += m[s[11]]
			v3 += v4
			v14 ^= v3
			v14 = v14<<(32-16) | v14>>16
			v9 += v14
			v4 ^= v9
			v4 = v4<<(32-12) | v4>>12

			v0 += m[s[15]]
			v0 += v5
			v15 ^= v0
			v15 = v15<<(32-8) | v15>>8
			v10 += v15
			v5 ^= v10
			v5 = v5<<(32-7) | v5>>7
			v1 += m[s[14]]
			v1 += v6
			v12 ^= v1
			v12 = v12<<(32-8) | v12>>8
			v11 += v12
			v6 ^= v11
			v6 = v6<<(32-7) | v6>>7
			v2 += m[s[12]]
			v2 += v7
			v13 ^= v2
			v13 = v13<<(32-8) | v13>>8
			v8 += v13
			v7 ^= v8
			v7 = v7<<(32-7) | v7>>7
			v3 += m[s[13]]
			v3 += v4
			v14 ^= v3
			v14 = v14<<(32-8) | v14>>8
			v9 += v14
			v4 ^= v9
			v4 = v4<<(32-7) | v4>>7
		}

		h0 ^= v0 ^ v8
		h1 ^= v1 ^ v9
		h2 ^= v2 ^ v10
		h3 ^= v3 ^ v11
		h4 ^= v4 ^ v12
		h5 ^= v5 ^ v13
		h6 ^= v6 ^ v14
		h7 ^= v7 ^ v15
	}

	hVal[0], hVal[1], hVal[2], hVal[3] = h0, h1, h2, h3
	hVal[4], hVal[5], hVal[6], hVal[7] = h4, h5, h6, h7

	counter[0] = ctr0
	counter[1] = ctr1
}
