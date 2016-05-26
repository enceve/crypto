// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package chacha20

import "github.com/enceve/crypto/poly1305"

// The four RFC 7539 constants
const (
	const0 = 0x61707865
	const1 = 0x3320646e
	const2 = 0x79622d32
	const3 = 0x6b206574
)

// func genericXORKeyStream(dst, src []byte, key *[32]byte, nonce *[12]byte, ctr uint32, rounds int)
// can be found in chacha20_ref.go or in chacha20_amd64.go

// authenticate calculates the poly1305 tag from
// the given ciphertext and additional data.
func authenticate(key *[32]byte, ciphertext, additionalData []byte) []byte {
	ctLen := uint64(len(ciphertext))
	adLen := uint64(len(additionalData))
	padAD, padCT := adLen%16, ctLen%16

	var buf [16]byte
	buf[0] = byte(adLen)
	buf[1] = byte(adLen >> 8)
	buf[2] = byte(adLen >> 16)
	buf[3] = byte(adLen >> 24)
	buf[4] = byte(adLen >> 32)
	buf[5] = byte(adLen >> 40)
	buf[6] = byte(adLen >> 48)
	buf[7] = byte(adLen >> 56)
	buf[8] = byte(ctLen)
	buf[9] = byte(ctLen >> 8)
	buf[10] = byte(ctLen >> 16)
	buf[11] = byte(ctLen >> 24)
	buf[12] = byte(ctLen >> 32)
	buf[13] = byte(ctLen >> 40)
	buf[14] = byte(ctLen >> 48)
	buf[15] = byte(ctLen >> 56)

	poly, _ := poly1305.New(key[:])
	poly.Write(additionalData)
	if padAD > 0 {
		poly.Write(make([]byte, 16-padAD))
	}
	poly.Write(ciphertext)
	if padCT > 0 {
		poly.Write(make([]byte, 16-padCT))
	}
	poly.Write(buf[:])
	return poly.Sum(nil)
}

// Initialize the cipher with the key and the nonce
func initialize(key *[32]byte, nonce *[12]byte, state *[16]uint32) {
	// The four rfc constants
	state[0] = const0
	state[1] = const1
	state[2] = const2
	state[3] = const3

	// The 256 bit key
	state[4] = uint32(key[0]) | uint32(key[1])<<8 | uint32(key[2])<<16 | uint32(key[3])<<24
	state[5] = uint32(key[4]) | uint32(key[5])<<8 | uint32(key[6])<<16 | uint32(key[7])<<24
	state[6] = uint32(key[8]) | uint32(key[9])<<8 | uint32(key[10])<<16 | uint32(key[11])<<24
	state[7] = uint32(key[12]) | uint32(key[13])<<8 | uint32(key[14])<<16 | uint32(key[15])<<24
	state[8] = uint32(key[16]) | uint32(key[17])<<8 | uint32(key[18])<<16 | uint32(key[19])<<24
	state[9] = uint32(key[20]) | uint32(key[21])<<8 | uint32(key[22])<<16 | uint32(key[23])<<24
	state[10] = uint32(key[24]) | uint32(key[25])<<8 | uint32(key[26])<<16 | uint32(key[27])<<24
	state[11] = uint32(key[28]) | uint32(key[29])<<8 | uint32(key[30])<<16 | uint32(key[31])<<24

	// The counter
	state[12] = 0

	// The 96 bit nonce
	state[13] = uint32(nonce[0]) | uint32(nonce[1])<<8 | uint32(nonce[2])<<16 | uint32(nonce[3])<<24
	state[14] = uint32(nonce[4]) | uint32(nonce[5])<<8 | uint32(nonce[6])<<16 | uint32(nonce[7])<<24
	state[15] = uint32(nonce[8]) | uint32(nonce[9])<<8 | uint32(nonce[10])<<16 | uint32(nonce[11])<<24
}
