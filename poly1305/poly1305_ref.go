// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build !386

package poly1305

func initialize(r *[5]uint32, pad *[4]uint32, key *[32]byte) {
	r[0] = (uint32(key[0]) | uint32(key[1])<<8 | uint32(key[2])<<16 | uint32(key[3])<<24) & 0x3ffffff
	r[1] = ((uint32(key[3]) | uint32(key[4])<<8 | uint32(key[5])<<16 | uint32(key[6])<<24) >> 2) & 0x3ffff03
	r[2] = ((uint32(key[6]) | uint32(key[7])<<8 | uint32(key[8])<<16 | uint32(key[9])<<24) >> 4) & 0x3ffc0ff
	r[3] = ((uint32(key[9]) | uint32(key[10])<<8 | uint32(key[11])<<16 | uint32(key[12])<<24) >> 6) & 0x3f03fff
	r[4] = ((uint32(key[12]) | uint32(key[13])<<8 | uint32(key[14])<<16 | uint32(key[15])<<24) >> 8) & 0x00fffff

	pad[0] = (uint32(key[16]) | uint32(key[17])<<8 | uint32(key[18])<<16 | uint32(key[19])<<24)
	pad[1] = (uint32(key[20]) | uint32(key[21])<<8 | uint32(key[22])<<16 | uint32(key[23])<<24)
	pad[2] = (uint32(key[24]) | uint32(key[25])<<8 | uint32(key[26])<<16 | uint32(key[27])<<24)
	pad[3] = (uint32(key[28]) | uint32(key[29])<<8 | uint32(key[30])<<16 | uint32(key[31])<<24)
}

func unpackMessage(h0, h1, h2, h3, h4 *uint32, flag uint32, msg []byte) {
	*h0 += (uint32(msg[0]) | uint32(msg[1])<<8 | uint32(msg[2])<<16 | uint32(msg[3])<<24) & 0x3ffffff
	*h1 += ((uint32(msg[3]) | uint32(msg[4])<<8 | uint32(msg[5])<<16 | uint32(msg[6])<<24) >> 2) & 0x3ffffff
	*h2 += ((uint32(msg[6]) | uint32(msg[7])<<8 | uint32(msg[8])<<16 | uint32(msg[9])<<24) >> 4) & 0x3ffffff
	*h3 += ((uint32(msg[9]) | uint32(msg[10])<<8 | uint32(msg[11])<<16 | uint32(msg[12])<<24) >> 6) & 0x3ffffff
	*h4 += ((uint32(msg[12]) | uint32(msg[13])<<8 | uint32(msg[14])<<16 | uint32(msg[15])<<24) >> 8) | flag
}

func extractHash(tag *[16]byte, h0, h1, h2, h3 uint32) {
	tag[0] = byte(h0)
	tag[1] = byte(h0 >> 8)
	tag[2] = byte(h0 >> 16)
	tag[3] = byte(h0 >> 24)
	tag[4] = byte(h1)
	tag[5] = byte(h1 >> 8)
	tag[6] = byte(h1 >> 16)
	tag[7] = byte(h1 >> 24)
	tag[8] = byte(h2)
	tag[9] = byte(h2 >> 8)
	tag[10] = byte(h2 >> 16)
	tag[11] = byte(h2 >> 24)
	tag[12] = byte(h3)
	tag[13] = byte(h3 >> 8)
	tag[14] = byte(h3 >> 16)
	tag[15] = byte(h3 >> 24)
}
