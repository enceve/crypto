// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package poly1305

import "unsafe"

func initialize(r *[5]uint32, pad *[4]uint32, key *[32]byte) {
	k0 := *(*uint64)(unsafe.Pointer(&key[0]))
	k1 := *(*uint64)(unsafe.Pointer(&key[8]))

	r[0] = uint32(k0) & 0x3ffffff
	r[1] = uint32(k0>>26) & 0x3ffff03
	r[2] = (uint32((k0>>48)|(k1<<16)) >> 4) & 0x3ffc0ff
	r[3] = uint32(k1>>14) & 0x3f03fff
	r[4] = uint32(k1>>40) & 0x00fffff

	pad[0] = *(*uint32)(unsafe.Pointer(&key[16]))
	pad[1] = *(*uint32)(unsafe.Pointer(&key[20]))
	pad[2] = *(*uint32)(unsafe.Pointer(&key[24]))
	pad[3] = *(*uint32)(unsafe.Pointer(&key[28]))
}

func core(msg []byte, flag uint32, h, r *[5]uint32) {
	h0, h1, h2, h3, h4 := h[0], h[1], h[2], h[3], h[4]
	r0, r1, r2, r3, r4 := uint64(r[0]), uint64(r[1]), uint64(r[2]), uint64(r[3]), uint64(r[4])
	s1, s2, s3, s4 := uint64(r[1]*5), uint64(r[2]*5), uint64(r[3]*5), uint64(r[4]*5)

	var d0, d1, d2, d3, d4 uint64
	var m0, m1 uint64
	for i := 0; i < len(msg); i += TagSize {
		m0 = *(*uint64)(unsafe.Pointer(&msg[i]))
		m1 = *(*uint64)(unsafe.Pointer(&msg[i+8]))

		// h += m
		h0 += uint32(m0) & 0x3ffffff
		h1 += uint32(m0>>26) & 0x3ffffff
		h2 += (uint32((m0>>48)|(m1<<16)) >> 4) & 0x3ffffff
		h3 += uint32(m1>>14) & 0x3ffffff
		h4 += uint32(m1>>40) | flag

		// h *= r
		d0 = (uint64(h0) * r0) + (uint64(h1) * s4) + (uint64(h2) * s3) + (uint64(h3) * s2) + (uint64(h4) * s1)
		d1 = (d0 >> 26) + (uint64(h0) * r1) + (uint64(h1) * r0) + (uint64(h2) * s4) + (uint64(h3) * s3) + (uint64(h4) * s2)
		d2 = (d1 >> 26) + (uint64(h0) * r2) + (uint64(h1) * r1) + (uint64(h2) * r0) + (uint64(h3) * s4) + (uint64(h4) * s3)
		d3 = (d2 >> 26) + (uint64(h0) * r3) + (uint64(h1) * r2) + (uint64(h2) * r1) + (uint64(h3) * r0) + (uint64(h4) * s4)
		d4 = (d3 >> 26) + (uint64(h0) * r4) + (uint64(h1) * r3) + (uint64(h2) * r2) + (uint64(h3) * r1) + (uint64(h4) * r0)

		// h %= p
		h0 = uint32(d0) & 0x3ffffff
		h1 = uint32(d1) & 0x3ffffff
		h2 = uint32(d2) & 0x3ffffff
		h3 = uint32(d3) & 0x3ffffff
		h4 = uint32(d4) & 0x3ffffff

		h0 += uint32(d4>>26) * 5
		h1 += h0 >> 26
		h0 = h0 & 0x3ffffff
	}
	h[0], h[1], h[2], h[3], h[4] = h0, h1, h2, h3, h4
}

func extractHash(tag *[16]byte, h0, h1, h2, h3 uint32) {
	tagPtr := (*[2]uint64)(unsafe.Pointer(&tag[0]))
	tagPtr[0] = uint64(h0) | (uint64(h1) << 32)
	tagPtr[1] = uint64(h2) | (uint64(h3) << 32)
}
