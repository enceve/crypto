package blake2b

// the core blake2b function taking:
//  - the 8 64 bit chan vales
//  - the 2 64 counters
//  - the final block flag
//  - the message (multiply of the blocksize)
func update(hVal *[8]uint64, ctr *[2]uint64, f uint64, msg []byte) {
	h0, h1, h2, h3 := hVal[0], hVal[1], hVal[2], hVal[3]
	h4, h5, h6, h7 := hVal[4], hVal[5], hVal[6], hVal[7]
	var m [16]uint64

	ctrL := ctr[0]
	ctrH := ctr[1]

	length := len(msg)
	for i, j := 0, 0; i < length; i += BlockSize {
		ctrL += BlockSize
		if ctrL < BlockSize {
			ctrH++
		}
		v0, v1, v2, v3, v4, v5, v6, v7 := h0, h1, h2, h3, h4, h5, h6, h7
		v8, v9, v10, v11 := iv[0], iv[1], iv[2], iv[3]
		v12, v13, v14, v15 := iv[4], iv[5], iv[6], iv[7]
		v12 ^= ctrL
		v13 ^= ctrH
		v14 ^= f

		for k := range m {
			m[k] = uint64(msg[j]) | uint64(msg[j+1])<<8 | uint64(msg[j+2])<<16 | uint64(msg[j+3])<<24 |
				uint64(msg[j+4])<<32 | uint64(msg[j+5])<<40 | uint64(msg[j+6])<<48 | uint64(msg[j+7])<<56
			j += 8
		}

		for k := range precomputed {
			s := &(precomputed[k])

			v0 += m[s[0]]
			v0 += v4
			v12 ^= v0
			v12 = v12<<(64-32) | v12>>32
			v8 += v12
			v4 ^= v8
			v4 = v4<<(64-24) | v4>>24
			v1 += m[s[1]]
			v1 += v5
			v13 ^= v1
			v13 = v13<<(64-32) | v13>>32
			v9 += v13
			v5 ^= v9
			v5 = v5<<(64-24) | v5>>24
			v2 += m[s[2]]
			v2 += v6
			v14 ^= v2
			v14 = v14<<(64-32) | v14>>32
			v10 += v14
			v6 ^= v10
			v6 = v6<<(64-24) | v6>>24
			v3 += m[s[3]]
			v3 += v7
			v15 ^= v3
			v15 = v15<<(64-32) | v15>>32
			v11 += v15
			v7 ^= v11
			v7 = v7<<(64-24) | v7>>24
			v2 += m[s[4]]
			v2 += v6
			v14 ^= v2
			v14 = v14<<(64-16) | v14>>16
			v10 += v14
			v6 ^= v10
			v6 = v6<<(64-63) | v6>>63
			v3 += m[s[5]]
			v3 += v7
			v15 ^= v3
			v15 = v15<<(64-16) | v15>>16
			v11 += v15
			v7 ^= v11
			v7 = v7<<(64-63) | v7>>63
			v1 += m[s[6]]
			v1 += v5
			v13 ^= v1
			v13 = v13<<(64-16) | v13>>16
			v9 += v13
			v5 ^= v9
			v5 = v5<<(64-63) | v5>>63
			v0 += m[s[7]]
			v0 += v4
			v12 ^= v0
			v12 = v12<<(64-16) | v12>>16
			v8 += v12
			v4 ^= v8
			v4 = v4<<(64-63) | v4>>63
			v0 += m[s[8]]
			v0 += v5
			v15 ^= v0
			v15 = v15<<(64-32) | v15>>32
			v10 += v15
			v5 ^= v10
			v5 = v5<<(64-24) | v5>>24
			v1 += m[s[9]]
			v1 += v6
			v12 ^= v1
			v12 = v12<<(64-32) | v12>>32
			v11 += v12
			v6 ^= v11
			v6 = v6<<(64-24) | v6>>24
			v2 += m[s[10]]
			v2 += v7
			v13 ^= v2
			v13 = v13<<(64-32) | v13>>32
			v8 += v13
			v7 ^= v8
			v7 = v7<<(64-24) | v7>>24
			v3 += m[s[11]]
			v3 += v4
			v14 ^= v3
			v14 = v14<<(64-32) | v14>>32
			v9 += v14
			v4 ^= v9
			v4 = v4<<(64-24) | v4>>24
			v2 += m[s[12]]
			v2 += v7
			v13 ^= v2
			v13 = v13<<(64-16) | v13>>16
			v8 += v13
			v7 ^= v8
			v7 = v7<<(64-63) | v7>>63
			v3 += m[s[13]]
			v3 += v4
			v14 ^= v3
			v14 = v14<<(64-16) | v14>>16
			v9 += v14
			v4 ^= v9
			v4 = v4<<(64-63) | v4>>63
			v1 += m[s[14]]
			v1 += v6
			v12 ^= v1
			v12 = v12<<(64-16) | v12>>16
			v11 += v12
			v6 ^= v11
			v6 = v6<<(64-63) | v6>>63
			v0 += m[s[15]]
			v0 += v5
			v15 ^= v0
			v15 = v15<<(64-16) | v15>>16
			v10 += v15
			v5 ^= v10
			v5 = v5<<(64-63) | v5>>63
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

	ctr[0] = ctrL
	ctr[1] = ctrH
}
