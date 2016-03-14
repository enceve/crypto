// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package threefish

// Encrypt512 does a threefish-512 encryption operation
// using the expanded 512 bit key (sk), the 128 bit tweak and
// the 512 bit block (msg).
// The sk[8] must be sk[0] xor sk[1] xor ... sk[8] xor C240
// The tweak[2] must be tweak[0] xor tweak[1]
func Encrypt512(sk *[9]uint64, tweak *[3]uint64, msg *[8]uint64) {
	addKey512(sk, tweak, msg, 0)
	mixFirst512(msg)
	addKey512(sk, tweak, msg, 1)
	mixLast512(msg)

	addKey512(sk, tweak, msg, 2)
	mixFirst512(msg)
	addKey512(sk, tweak, msg, 3)
	mixLast512(msg)

	addKey512(sk, tweak, msg, 4)
	mixFirst512(msg)
	addKey512(sk, tweak, msg, 5)
	mixLast512(msg)

	addKey512(sk, tweak, msg, 6)
	mixFirst512(msg)
	addKey512(sk, tweak, msg, 7)
	mixLast512(msg)

	addKey512(sk, tweak, msg, 8)
	mixFirst512(msg)
	addKey512(sk, tweak, msg, 9)
	mixLast512(msg)

	addKey512(sk, tweak, msg, 10)
	mixFirst512(msg)
	addKey512(sk, tweak, msg, 11)
	mixLast512(msg)

	addKey512(sk, tweak, msg, 12)
	mixFirst512(msg)
	addKey512(sk, tweak, msg, 13)
	mixLast512(msg)

	addKey512(sk, tweak, msg, 14)
	mixFirst512(msg)
	addKey512(sk, tweak, msg, 15)
	mixLast512(msg)

	addKey512(sk, tweak, msg, 16)
	mixFirst512(msg)
	addKey512(sk, tweak, msg, 17)
	mixLast512(msg)

	addKey512(sk, tweak, msg, 18)
}

// Decrypt512 does a threefish-512 decryption operation
// using the expanded 512 bit key (sk), the 128 bit tweak and
// the 512 bit block (msg).
// The sk[8] must be sk[0] xor sk[1] xor ... sk[8] xor C240
// The tweak[2] must be tweak[0] xor tweak[1]
func Decrypt512(sk *[9]uint64, tweak *[3]uint64, msg *[8]uint64) {
	subKey512(sk, tweak, msg, 18)
	mixLast512Inv(msg)
	subKey512(sk, tweak, msg, 17)
	mixFirst512Inv(msg)

	subKey512(sk, tweak, msg, 16)
	mixLast512Inv(msg)
	subKey512(sk, tweak, msg, 15)
	mixFirst512Inv(msg)

	subKey512(sk, tweak, msg, 14)
	mixLast512Inv(msg)
	subKey512(sk, tweak, msg, 13)
	mixFirst512Inv(msg)

	subKey512(sk, tweak, msg, 12)
	mixLast512Inv(msg)
	subKey512(sk, tweak, msg, 11)
	mixFirst512Inv(msg)

	subKey512(sk, tweak, msg, 10)
	mixLast512Inv(msg)
	subKey512(sk, tweak, msg, 9)
	mixFirst512Inv(msg)

	subKey512(sk, tweak, msg, 8)
	mixLast512Inv(msg)
	subKey512(sk, tweak, msg, 7)
	mixFirst512Inv(msg)

	subKey512(sk, tweak, msg, 6)
	mixLast512Inv(msg)
	subKey512(sk, tweak, msg, 5)
	mixFirst512Inv(msg)

	subKey512(sk, tweak, msg, 4)
	mixLast512Inv(msg)
	subKey512(sk, tweak, msg, 3)
	mixFirst512Inv(msg)

	subKey512(sk, tweak, msg, 2)
	mixLast512Inv(msg)
	subKey512(sk, tweak, msg, 1)
	mixFirst512Inv(msg)

	subKey512(sk, tweak, msg, 0)
}

// adds the 512 bit key and the 128 bit tweak
// with the message block
// the added key and tweak depends on the round
func addKey512(sk *[9]uint64, tweak *[3]uint64, msg *[8]uint64, r int) {
	msg[0] += sk[r%9]
	msg[1] += sk[(r+1)%9]
	msg[2] += sk[(r+2)%9]
	msg[3] += sk[(r+3)%9]
	msg[4] += sk[(r+4)%9]
	msg[5] += sk[(r+5)%9] + tweak[r%3]
	msg[6] += sk[(r+6)%9] + tweak[(r+1)%3]
	msg[7] += sk[(r+7)%9] + uint64(r)
}

// subs the 512 bit key and the 128 bit tweak
// from the message block
// the subtracted key and tweak depends on the round
func subKey512(sk *[9]uint64, tweak *[3]uint64, msg *[8]uint64, r int) {
	msg[0] -= sk[r%9]
	msg[1] -= sk[(r+1)%9]
	msg[2] -= sk[(r+2)%9]
	msg[3] -= sk[(r+3)%9]
	msg[4] -= sk[(r+4)%9]
	msg[5] -= sk[(r+5)%9] + tweak[r%3]
	msg[6] -= sk[(r+6)%9] + tweak[(r+1)%3]
	msg[7] -= sk[(r+7)%9] + uint64(r)
}

// the first 4x8 mix operations
func mixFirst512(msg *[8]uint64) {
	msg[0] += msg[1]
	msg[1] = (msg[1]<<46 | msg[1]>>(64-46)) ^ msg[0]
	msg[2] += msg[3]
	msg[3] = (msg[3]<<36 | msg[3]>>(64-36)) ^ msg[2]
	msg[4] += msg[5]
	msg[5] = (msg[5]<<19 | msg[5]>>(64-19)) ^ msg[4]
	msg[6] += msg[7]
	msg[7] = (msg[7]<<37 | msg[7]>>(64-37)) ^ msg[6]

	msg[2] += msg[1]
	msg[1] = (msg[1]<<33 | msg[1]>>(64-33)) ^ msg[2]
	msg[4] += msg[7]
	msg[7] = (msg[7]<<27 | msg[7]>>(64-27)) ^ msg[4]
	msg[6] += msg[5]
	msg[5] = (msg[5]<<14 | msg[5]>>(64-14)) ^ msg[6]
	msg[0] += msg[3]
	msg[3] = (msg[3]<<42 | msg[3]>>(64-42)) ^ msg[0]

	msg[4] += msg[1]
	msg[1] = (msg[1]<<17 | msg[1]>>(64-17)) ^ msg[4]
	msg[6] += msg[3]
	msg[3] = (msg[3]<<49 | msg[3]>>(64-49)) ^ msg[6]
	msg[0] += msg[5]
	msg[5] = (msg[5]<<36 | msg[5]>>(64-36)) ^ msg[0]
	msg[2] += msg[7]
	msg[7] = (msg[7]<<39 | msg[7]>>(64-39)) ^ msg[2]

	msg[6] += msg[1]
	msg[1] = (msg[1]<<44 | msg[1]>>(64-44)) ^ msg[6]
	msg[0] += msg[7]
	msg[7] = (msg[7]<<9 | msg[7]>>(64-9)) ^ msg[0]
	msg[2] += msg[5]
	msg[5] = (msg[5]<<54 | msg[5]>>(64-54)) ^ msg[2]
	msg[4] += msg[3]
	msg[3] = (msg[3]<<56 | msg[3]>>(64-56)) ^ msg[4]
}

// the inverse of the first 4x8 mix operations
func mixFirst512Inv(msg *[8]uint64) {
	tmp := msg[3] ^ msg[4]
	msg[3] = tmp>>56 | tmp<<(64-56)
	msg[4] -= msg[3]
	tmp = msg[5] ^ msg[2]
	msg[5] = tmp>>54 | tmp<<(64-54)
	msg[2] -= msg[5]
	tmp = msg[7] ^ msg[0]
	msg[7] = tmp>>9 | tmp<<(64-9)
	msg[0] -= msg[7]
	tmp = msg[1] ^ msg[6]
	msg[1] = tmp>>44 | tmp<<(64-44)
	msg[6] -= msg[1]

	tmp = msg[7] ^ msg[2]
	msg[7] = tmp>>39 | tmp<<(64-39)
	msg[2] -= msg[7]
	tmp = msg[5] ^ msg[0]
	msg[5] = tmp>>36 | tmp<<(64-36)
	msg[0] -= msg[5]
	tmp = msg[3] ^ msg[6]
	msg[3] = tmp>>49 | tmp<<(64-49)
	msg[6] -= msg[3]
	tmp = msg[1] ^ msg[4]
	msg[1] = tmp>>17 | tmp<<(64-17)
	msg[4] -= msg[1]

	tmp = msg[3] ^ msg[0]
	msg[3] = tmp>>42 | tmp<<(64-42)
	msg[0] -= msg[3]
	tmp = msg[5] ^ msg[6]
	msg[5] = tmp>>14 | tmp<<(64-14)
	msg[6] -= msg[5]
	tmp = msg[7] ^ msg[4]
	msg[7] = tmp>>27 | tmp<<(64-27)
	msg[4] -= msg[7]
	tmp = msg[1] ^ msg[2]
	msg[1] = tmp>>33 | tmp<<(64-33)
	msg[2] -= msg[1]

	tmp = msg[7] ^ msg[6]
	msg[7] = tmp>>37 | tmp<<(64-37)
	msg[6] -= msg[7]
	tmp = msg[5] ^ msg[4]
	msg[5] = tmp>>19 | tmp<<(64-19)
	msg[4] -= msg[5]
	tmp = msg[3] ^ msg[2]
	msg[3] = tmp>>36 | tmp<<(64-36)
	msg[2] -= msg[3]
	tmp = msg[1] ^ msg[0]
	msg[1] = tmp>>46 | tmp<<(64-46)
	msg[0] -= msg[1]
}

// the last 4x8 mix operations
func mixLast512(msg *[8]uint64) {
	msg[0] += msg[1]
	msg[1] = (msg[1]<<39 | msg[1]>>(64-39)) ^ msg[0]
	msg[2] += msg[3]
	msg[3] = (msg[3]<<30 | msg[3]>>(64-30)) ^ msg[2]
	msg[4] += msg[5]
	msg[5] = (msg[5]<<34 | msg[5]>>(64-34)) ^ msg[4]
	msg[6] += msg[7]
	msg[7] = (msg[7]<<24 | msg[7]>>(64-24)) ^ msg[6]

	msg[2] += msg[1]
	msg[1] = (msg[1]<<13 | msg[1]>>(64-13)) ^ msg[2]
	msg[4] += msg[7]
	msg[7] = (msg[7]<<50 | msg[7]>>(64-50)) ^ msg[4]
	msg[6] += msg[5]
	msg[5] = (msg[5]<<10 | msg[5]>>(64-10)) ^ msg[6]
	msg[0] += msg[3]
	msg[3] = (msg[3]<<17 | msg[3]>>(64-17)) ^ msg[0]

	msg[4] += msg[1]
	msg[1] = (msg[1]<<25 | msg[1]>>(64-25)) ^ msg[4]
	msg[6] += msg[3]
	msg[3] = (msg[3]<<29 | msg[3]>>(64-29)) ^ msg[6]
	msg[0] += msg[5]
	msg[5] = (msg[5]<<39 | msg[5]>>(64-39)) ^ msg[0]
	msg[2] += msg[7]
	msg[7] = (msg[7]<<43 | msg[7]>>(64-43)) ^ msg[2]

	msg[6] += msg[1]
	msg[1] = (msg[1]<<8 | msg[1]>>(64-8)) ^ msg[6]
	msg[0] += msg[7]
	msg[7] = (msg[7]<<35 | msg[7]>>(64-35)) ^ msg[0]
	msg[2] += msg[5]
	msg[5] = (msg[5]<<56 | msg[5]>>(64-56)) ^ msg[2]
	msg[4] += msg[3]
	msg[3] = (msg[3]<<22 | msg[3]>>(64-22)) ^ msg[4]
}

// the inverse of the last 4x8 mix operations
func mixLast512Inv(msg *[8]uint64) {
	tmp := msg[3] ^ msg[4]
	msg[3] = tmp>>22 | tmp<<(64-22)
	msg[4] -= msg[3]
	tmp = msg[5] ^ msg[2]
	msg[5] = tmp>>56 | tmp<<(64-56)
	msg[2] -= msg[5]
	tmp = msg[7] ^ msg[0]
	msg[7] = tmp>>35 | tmp<<(64-35)
	msg[0] -= msg[7]
	tmp = msg[1] ^ msg[6]
	msg[1] = tmp>>8 | tmp<<(64-8)
	msg[6] -= msg[1]

	tmp = msg[7] ^ msg[2]
	msg[7] = tmp>>43 | tmp<<(64-43)
	msg[2] -= msg[7]
	tmp = msg[5] ^ msg[0]
	msg[5] = tmp>>39 | tmp<<(64-39)
	msg[0] -= msg[5]
	tmp = msg[3] ^ msg[6]
	msg[3] = tmp>>29 | tmp<<(64-29)
	msg[6] -= msg[3]
	tmp = msg[1] ^ msg[4]
	msg[1] = tmp>>25 | tmp<<(64-25)
	msg[4] -= msg[1]

	tmp = msg[3] ^ msg[0]
	msg[3] = tmp>>17 | tmp<<(64-17)
	msg[0] -= msg[3]
	tmp = msg[5] ^ msg[6]
	msg[5] = tmp>>10 | tmp<<(64-10)
	msg[6] -= msg[5]
	tmp = msg[7] ^ msg[4]
	msg[7] = tmp>>50 | tmp<<(64-50)
	msg[4] -= msg[7]
	tmp = msg[1] ^ msg[2]
	msg[1] = tmp>>13 | tmp<<(64-13)
	msg[2] -= msg[1]

	tmp = msg[7] ^ msg[6]
	msg[7] = tmp>>24 | tmp<<(64-24)
	msg[6] -= msg[7]
	tmp = msg[5] ^ msg[4]
	msg[5] = tmp>>34 | tmp<<(64-34)
	msg[4] -= msg[5]
	tmp = msg[3] ^ msg[2]
	msg[3] = tmp>>30 | tmp<<(64-30)
	msg[2] -= msg[3]
	tmp = msg[1] ^ msg[0]
	msg[1] = tmp>>39 | tmp<<(64-39)
	msg[0] -= msg[1]
}
