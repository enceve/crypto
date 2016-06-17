// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package poly1305

import "unsafe"

func initialize(r *[5]uint32, pad *[4]uint32, key *[32]byte) {
	r[0] = *(*uint32)(unsafe.Pointer(&key[0])) & 0x3ffffff
	r[1] = (*(*uint32)(unsafe.Pointer(&key[3])) >> 2) & 0x3ffff03
	r[2] = (*(*uint32)(unsafe.Pointer(&key[6])) >> 4) & 0x3ffc0ff
	r[3] = (*(*uint32)(unsafe.Pointer(&key[9])) >> 6) & 0x3f03fff
	r[4] = (*(*uint32)(unsafe.Pointer(&key[12])) >> 8) & 0x00fffff

	pad[0] = *(*uint32)(unsafe.Pointer(&key[16]))
	pad[1] = *(*uint32)(unsafe.Pointer(&key[20]))
	pad[2] = *(*uint32)(unsafe.Pointer(&key[24]))
	pad[3] = *(*uint32)(unsafe.Pointer(&key[28]))
}

func unpackMessage(h0, h1, h2, h3, h4 *uint32, flag uint32, msg []byte) {
	*h0 += *(*uint32)(unsafe.Pointer(&msg[0])) & 0x3ffffff
	*h1 += (*(*uint32)(unsafe.Pointer(&msg[3])) >> 2) & 0x3ffffff
	*h2 += (*(*uint32)(unsafe.Pointer(&msg[6])) >> 4) & 0x3ffffff
	*h3 += (*(*uint32)(unsafe.Pointer(&msg[9])) >> 6) & 0x3ffffff
	*h4 += (*(*uint32)(unsafe.Pointer(&msg[12])) >> 8) | flag
}

func extractHash(tag *[16]byte, h0, h1, h2, h3 uint32) {
	tagPtr := (*[4]uint32)(unsafe.Pointer(&tag[0]))
	tagPtr[0] = h0
	tagPtr[1] = h1
	tagPtr[2] = h2
	tagPtr[3] = h3
}
