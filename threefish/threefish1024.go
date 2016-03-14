// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package threefish

// Encrypt1024 does a threefish-1024 encryption operation
// using the expanded 1024 bit key (sk), the 128 bit tweak and
// the 1024 bit block (msg).
// The sk[16] must be sk[0] xor sk[1] xor ... sk[15] xor C240
// The tweak[2] must be tweak[0] xor tweak[1]
func Encrypt1024(sk *[17]uint64, tweak *[3]uint64, msg *[16]uint64) {
	addKey1024(sk, tweak, msg, 0)
	mixFirst1024(msg)
	addKey1024(sk, tweak, msg, 1)
	mixLast1024(msg)

	addKey1024(sk, tweak, msg, 2)
	mixFirst1024(msg)
	addKey1024(sk, tweak, msg, 3)
	mixLast1024(msg)

	addKey1024(sk, tweak, msg, 4)
	mixFirst1024(msg)
	addKey1024(sk, tweak, msg, 5)
	mixLast1024(msg)

	addKey1024(sk, tweak, msg, 6)
	mixFirst1024(msg)
	addKey1024(sk, tweak, msg, 7)
	mixLast1024(msg)

	addKey1024(sk, tweak, msg, 8)
	mixFirst1024(msg)
	addKey1024(sk, tweak, msg, 9)
	mixLast1024(msg)

	addKey1024(sk, tweak, msg, 10)
	mixFirst1024(msg)
	addKey1024(sk, tweak, msg, 11)
	mixLast1024(msg)

	addKey1024(sk, tweak, msg, 12)
	mixFirst1024(msg)
	addKey1024(sk, tweak, msg, 13)
	mixLast1024(msg)

	addKey1024(sk, tweak, msg, 14)
	mixFirst1024(msg)
	addKey1024(sk, tweak, msg, 15)
	mixLast1024(msg)

	addKey1024(sk, tweak, msg, 16)
	mixFirst1024(msg)
	addKey1024(sk, tweak, msg, 17)
	mixLast1024(msg)

	addKey1024(sk, tweak, msg, 18)
	mixFirst1024(msg)
	addKey1024(sk, tweak, msg, 19)
	mixLast1024(msg)

	addKey1024(sk, tweak, msg, 20)
}

// Decrypt1024 does a threefish-1024 decryption operation
// using the expanded 1024 bit key (sk), the 128 bit tweak and
// the 1024 bit block (msg).
// The sk[16] must be sk[0] xor sk[1] xor ... sk[15] xor C240
// The tweak[2] must be tweak[0] xor tweak[1]
func Decrypt1024(sk *[17]uint64, tweak *[3]uint64, msg *[16]uint64) {
	subKey1024(sk, tweak, msg, 20)
	mixLast1024Inv(msg)
	subKey1024(sk, tweak, msg, 19)
	mixFirst1024Inv(msg)

	subKey1024(sk, tweak, msg, 18)
	mixLast1024Inv(msg)
	subKey1024(sk, tweak, msg, 17)
	mixFirst1024Inv(msg)

	subKey1024(sk, tweak, msg, 16)
	mixLast1024Inv(msg)
	subKey1024(sk, tweak, msg, 15)
	mixFirst1024Inv(msg)

	subKey1024(sk, tweak, msg, 14)
	mixLast1024Inv(msg)
	subKey1024(sk, tweak, msg, 13)
	mixFirst1024Inv(msg)

	subKey1024(sk, tweak, msg, 12)
	mixLast1024Inv(msg)
	subKey1024(sk, tweak, msg, 11)
	mixFirst1024Inv(msg)

	subKey1024(sk, tweak, msg, 10)
	mixLast1024Inv(msg)
	subKey1024(sk, tweak, msg, 9)
	mixFirst1024Inv(msg)

	subKey1024(sk, tweak, msg, 8)
	mixLast1024Inv(msg)
	subKey1024(sk, tweak, msg, 7)
	mixFirst1024Inv(msg)

	subKey1024(sk, tweak, msg, 6)
	mixLast1024Inv(msg)
	subKey1024(sk, tweak, msg, 5)
	mixFirst1024Inv(msg)

	subKey1024(sk, tweak, msg, 4)
	mixLast1024Inv(msg)
	subKey1024(sk, tweak, msg, 3)
	mixFirst1024Inv(msg)

	subKey1024(sk, tweak, msg, 2)
	mixLast1024Inv(msg)
	subKey1024(sk, tweak, msg, 1)
	mixFirst1024Inv(msg)

	subKey1024(sk, tweak, msg, 0)
}

// adds the 1024 bit key and the 128 bit tweak
// with the message block
// the added key and tweak depends on the round
func addKey1024(sk *[17]uint64, tweak *[3]uint64, msg *[16]uint64, r int) {
	msg[0] += sk[r%17]
	msg[1] += sk[(r+1)%17]
	msg[2] += sk[(r+2)%17]
	msg[3] += sk[(r+3)%17]
	msg[4] += sk[(r+4)%17]
	msg[5] += sk[(r+5)%17]
	msg[6] += sk[(r+6)%17]
	msg[7] += sk[(r+7)%17]
	msg[8] += sk[(r+8)%17]
	msg[9] += sk[(r+9)%17]
	msg[10] += sk[(r+10)%17]
	msg[11] += sk[(r+11)%17]
	msg[12] += sk[(r+12)%17]
	msg[13] += sk[(r+13)%17] + tweak[r%3]
	msg[14] += sk[(r+14)%17] + tweak[(r+1)%3]
	msg[15] += sk[(r+15)%17] + uint64(r)
}

// subs the 1024 bit key and the 128 bit tweak
// from the message block
// the subtracted key and tweak depends on the round
func subKey1024(sk *[17]uint64, tweak *[3]uint64, msg *[16]uint64, r int) {
	msg[0] -= sk[r%17]
	msg[1] -= sk[(r+1)%17]
	msg[2] -= sk[(r+2)%17]
	msg[3] -= sk[(r+3)%17]
	msg[4] -= sk[(r+4)%17]
	msg[5] -= sk[(r+5)%17]
	msg[6] -= sk[(r+6)%17]
	msg[7] -= sk[(r+7)%17]
	msg[8] -= sk[(r+8)%17]
	msg[9] -= sk[(r+9)%17]
	msg[10] -= sk[(r+10)%17]
	msg[11] -= sk[(r+11)%17]
	msg[12] -= sk[(r+12)%17]
	msg[13] -= sk[(r+13)%17] + tweak[r%3]
	msg[14] -= sk[(r+14)%17] + tweak[(r+1)%3]
	msg[15] -= sk[(r+15)%17] + uint64(r)
}

// the first 4x16 mix operations
func mixFirst1024(msg *[16]uint64) {
	msg[0] += msg[1]
	msg[1] = ((msg[1] << 24) | (msg[1] >> (64 - 24))) ^ msg[0]
	msg[2] += msg[3]
	msg[3] = ((msg[3] << 13) | (msg[3] >> (64 - 13))) ^ msg[2]
	msg[4] += msg[5]
	msg[5] = ((msg[5] << 8) | (msg[5] >> (64 - 8))) ^ msg[4]
	msg[6] += msg[7]
	msg[7] = ((msg[7] << 47) | (msg[7] >> (64 - 47))) ^ msg[6]
	msg[8] += msg[9]
	msg[9] = ((msg[9] << 8) | (msg[9] >> (64 - 8))) ^ msg[8]
	msg[10] += msg[11]
	msg[11] = ((msg[11] << 17) | (msg[11] >> (64 - 17))) ^ msg[10]
	msg[12] += msg[13]
	msg[13] = ((msg[13] << 22) | (msg[13] >> (64 - 22))) ^ msg[12]
	msg[14] += msg[15]
	msg[15] = ((msg[15] << 37) | (msg[15] >> (64 - 37))) ^ msg[14]

	msg[0] += msg[9]
	msg[9] = ((msg[9] << 38) | (msg[9] >> (64 - 38))) ^ msg[0]
	msg[2] += msg[13]
	msg[13] = ((msg[13] << 19) | (msg[13] >> (64 - 19))) ^ msg[2]
	msg[6] += msg[11]
	msg[11] = ((msg[11] << 10) | (msg[11] >> (64 - 10))) ^ msg[6]
	msg[4] += msg[15]
	msg[15] = ((msg[15] << 55) | (msg[15] >> (64 - 55))) ^ msg[4]
	msg[10] += msg[7]
	msg[7] = ((msg[7] << 49) | (msg[7] >> (64 - 49))) ^ msg[10]
	msg[12] += msg[3]
	msg[3] = ((msg[3] << 18) | (msg[3] >> (64 - 18))) ^ msg[12]
	msg[14] += msg[5]
	msg[5] = ((msg[5] << 23) | (msg[5] >> (64 - 23))) ^ msg[14]
	msg[8] += msg[1]
	msg[1] = ((msg[1] << 52) | (msg[1] >> (64 - 52))) ^ msg[8]

	msg[0] += msg[7]
	msg[7] = ((msg[7] << 33) | (msg[7] >> (64 - 33))) ^ msg[0]
	msg[2] += msg[5]
	msg[5] = ((msg[5] << 4) | (msg[5] >> (64 - 4))) ^ msg[2]
	msg[4] += msg[3]
	msg[3] = ((msg[3] << 51) | (msg[3] >> (64 - 51))) ^ msg[4]
	msg[6] += msg[1]
	msg[1] = ((msg[1] << 13) | (msg[1] >> (64 - 13))) ^ msg[6]
	msg[12] += msg[15]
	msg[15] = ((msg[15] << 34) | (msg[15] >> (64 - 34))) ^ msg[12]
	msg[14] += msg[13]
	msg[13] = ((msg[13] << 41) | (msg[13] >> (64 - 41))) ^ msg[14]
	msg[8] += msg[11]
	msg[11] = ((msg[11] << 59) | (msg[11] >> (64 - 59))) ^ msg[8]
	msg[10] += msg[9]
	msg[9] = ((msg[9] << 17) | (msg[9] >> (64 - 17))) ^ msg[10]

	msg[0] += msg[15]
	msg[15] = ((msg[15] << 5) | (msg[15] >> (64 - 5))) ^ msg[0]
	msg[2] += msg[11]
	msg[11] = ((msg[11] << 20) | (msg[11] >> (64 - 20))) ^ msg[2]
	msg[6] += msg[13]
	msg[13] = ((msg[13] << 48) | (msg[13] >> (64 - 48))) ^ msg[6]
	msg[4] += msg[9]
	msg[9] = ((msg[9] << 41) | (msg[9] >> (64 - 41))) ^ msg[4]
	msg[14] += msg[1]
	msg[1] = ((msg[1] << 47) | (msg[1] >> (64 - 47))) ^ msg[14]
	msg[8] += msg[5]
	msg[5] = ((msg[5] << 28) | (msg[5] >> (64 - 28))) ^ msg[8]
	msg[10] += msg[3]
	msg[3] = ((msg[3] << 16) | (msg[3] >> (64 - 16))) ^ msg[10]
	msg[12] += msg[7]
	msg[7] = ((msg[7] << 25) | (msg[7] >> (64 - 25))) ^ msg[12]
}

// the inverse of the first 4x16 mix operations
func mixFirst1024Inv(msg *[16]uint64) {
	tmp := msg[7] ^ msg[12]
	msg[7] = (tmp >> 25) | (tmp << (64 - 25))
	msg[12] -= msg[7]
	tmp = msg[3] ^ msg[10]
	msg[3] = (tmp >> 16) | (tmp << (64 - 16))
	msg[10] -= msg[3]
	tmp = msg[5] ^ msg[8]
	msg[5] = (tmp >> 28) | (tmp << (64 - 28))
	msg[8] -= msg[5]
	tmp = msg[1] ^ msg[14]
	msg[1] = (tmp >> 47) | (tmp << (64 - 47))
	msg[14] -= msg[1]
	tmp = msg[9] ^ msg[4]
	msg[9] = (tmp >> 41) | (tmp << (64 - 41))
	msg[4] -= msg[9]
	tmp = msg[13] ^ msg[6]
	msg[13] = (tmp >> 48) | (tmp << (64 - 48))
	msg[6] -= msg[13]
	tmp = msg[11] ^ msg[2]
	msg[11] = (tmp >> 20) | (tmp << (64 - 20))
	msg[2] -= msg[11]
	tmp = msg[15] ^ msg[0]
	msg[15] = (tmp >> 5) | (tmp << (64 - 5))
	msg[0] -= msg[15]

	tmp = msg[9] ^ msg[10]
	msg[9] = (tmp >> 17) | (tmp << (64 - 17))
	msg[10] -= msg[9]
	tmp = msg[11] ^ msg[8]
	msg[11] = (tmp >> 59) | (tmp << (64 - 59))
	msg[8] -= msg[11]
	tmp = msg[13] ^ msg[14]
	msg[13] = (tmp >> 41) | (tmp << (64 - 41))
	msg[14] -= msg[13]
	tmp = msg[15] ^ msg[12]
	msg[15] = (tmp >> 34) | (tmp << (64 - 34))
	msg[12] -= msg[15]
	tmp = msg[1] ^ msg[6]
	msg[1] = (tmp >> 13) | (tmp << (64 - 13))
	msg[6] -= msg[1]
	tmp = msg[3] ^ msg[4]
	msg[3] = (tmp >> 51) | (tmp << (64 - 51))
	msg[4] -= msg[3]
	tmp = msg[5] ^ msg[2]
	msg[5] = (tmp >> 4) | (tmp << (64 - 4))
	msg[2] -= msg[5]
	tmp = msg[7] ^ msg[0]
	msg[7] = (tmp >> 33) | (tmp << (64 - 33))
	msg[0] -= msg[7]

	tmp = msg[1] ^ msg[8]
	msg[1] = (tmp >> 52) | (tmp << (64 - 52))
	msg[8] -= msg[1]
	tmp = msg[5] ^ msg[14]
	msg[5] = (tmp >> 23) | (tmp << (64 - 23))
	msg[14] -= msg[5]
	tmp = msg[3] ^ msg[12]
	msg[3] = (tmp >> 18) | (tmp << (64 - 18))
	msg[12] -= msg[3]
	tmp = msg[7] ^ msg[10]
	msg[7] = (tmp >> 49) | (tmp << (64 - 49))
	msg[10] -= msg[7]
	tmp = msg[15] ^ msg[4]
	msg[15] = (tmp >> 55) | (tmp << (64 - 55))
	msg[4] -= msg[15]
	tmp = msg[11] ^ msg[6]
	msg[11] = (tmp >> 10) | (tmp << (64 - 10))
	msg[6] -= msg[11]
	tmp = msg[13] ^ msg[2]
	msg[13] = (tmp >> 19) | (tmp << (64 - 19))
	msg[2] -= msg[13]
	tmp = msg[9] ^ msg[0]
	msg[9] = (tmp >> 38) | (tmp << (64 - 38))
	msg[0] -= msg[9]

	tmp = msg[15] ^ msg[14]
	msg[15] = (tmp >> 37) | (tmp << (64 - 37))
	msg[14] -= msg[15]
	tmp = msg[13] ^ msg[12]
	msg[13] = (tmp >> 22) | (tmp << (64 - 22))
	msg[12] -= msg[13]
	tmp = msg[11] ^ msg[10]
	msg[11] = (tmp >> 17) | (tmp << (64 - 17))
	msg[10] -= msg[11]
	tmp = msg[9] ^ msg[8]
	msg[9] = (tmp >> 8) | (tmp << (64 - 8))
	msg[8] -= msg[9]
	tmp = msg[7] ^ msg[6]
	msg[7] = (tmp >> 47) | (tmp << (64 - 47))
	msg[6] -= msg[7]
	tmp = msg[5] ^ msg[4]
	msg[5] = (tmp >> 8) | (tmp << (64 - 8))
	msg[4] -= msg[5]
	tmp = msg[3] ^ msg[2]
	msg[3] = (tmp >> 13) | (tmp << (64 - 13))
	msg[2] -= msg[3]
	tmp = msg[1] ^ msg[0]
	msg[1] = (tmp >> 24) | (tmp << (64 - 24))
	msg[0] -= msg[1]
}

// the last 4x16 mix operations
func mixLast1024(msg *[16]uint64) {
	msg[0] += msg[1]
	msg[1] = ((msg[1] << 41) | (msg[1] >> (64 - 41))) ^ msg[0]
	msg[2] += msg[3]
	msg[3] = ((msg[3] << 9) | (msg[3] >> (64 - 9))) ^ msg[2]
	msg[4] += msg[5]
	msg[5] = ((msg[5] << 37) | (msg[5] >> (64 - 37))) ^ msg[4]
	msg[6] += msg[7]
	msg[7] = ((msg[7] << 31) | (msg[7] >> (64 - 31))) ^ msg[6]
	msg[8] += msg[9]
	msg[9] = ((msg[9] << 12) | (msg[9] >> (64 - 12))) ^ msg[8]
	msg[10] += msg[11]
	msg[11] = ((msg[11] << 47) | (msg[11] >> (64 - 47))) ^ msg[10]
	msg[12] += msg[13]
	msg[13] = ((msg[13] << 44) | (msg[13] >> (64 - 44))) ^ msg[12]
	msg[14] += msg[15]
	msg[15] = ((msg[15] << 30) | (msg[15] >> (64 - 30))) ^ msg[14]

	msg[0] += msg[9]
	msg[9] = ((msg[9] << 16) | (msg[9] >> (64 - 16))) ^ msg[0]
	msg[2] += msg[13]
	msg[13] = ((msg[13] << 34) | (msg[13] >> (64 - 34))) ^ msg[2]
	msg[6] += msg[11]
	msg[11] = ((msg[11] << 56) | (msg[11] >> (64 - 56))) ^ msg[6]
	msg[4] += msg[15]
	msg[15] = ((msg[15] << 51) | (msg[15] >> (64 - 51))) ^ msg[4]
	msg[10] += msg[7]
	msg[7] = ((msg[7] << 4) | (msg[7] >> (64 - 4))) ^ msg[10]
	msg[12] += msg[3]
	msg[3] = ((msg[3] << 53) | (msg[3] >> (64 - 53))) ^ msg[12]
	msg[14] += msg[5]
	msg[5] = ((msg[5] << 42) | (msg[5] >> (64 - 42))) ^ msg[14]
	msg[8] += msg[1]
	msg[1] = ((msg[1] << 41) | (msg[1] >> (64 - 41))) ^ msg[8]

	msg[0] += msg[7]
	msg[7] = ((msg[7] << 31) | (msg[7] >> (64 - 31))) ^ msg[0]
	msg[2] += msg[5]
	msg[5] = ((msg[5] << 44) | (msg[5] >> (64 - 44))) ^ msg[2]
	msg[4] += msg[3]
	msg[3] = ((msg[3] << 47) | (msg[3] >> (64 - 47))) ^ msg[4]
	msg[6] += msg[1]
	msg[1] = ((msg[1] << 46) | (msg[1] >> (64 - 46))) ^ msg[6]
	msg[12] += msg[15]
	msg[15] = ((msg[15] << 19) | (msg[15] >> (64 - 19))) ^ msg[12]
	msg[14] += msg[13]
	msg[13] = ((msg[13] << 42) | (msg[13] >> (64 - 42))) ^ msg[14]
	msg[8] += msg[11]
	msg[11] = ((msg[11] << 44) | (msg[11] >> (64 - 44))) ^ msg[8]
	msg[10] += msg[9]
	msg[9] = ((msg[9] << 25) | (msg[9] >> (64 - 25))) ^ msg[10]

	msg[0] += msg[15]
	msg[15] = ((msg[15] << 9) | (msg[15] >> (64 - 9))) ^ msg[0]
	msg[2] += msg[11]
	msg[11] = ((msg[11] << 48) | (msg[11] >> (64 - 48))) ^ msg[2]
	msg[6] += msg[13]
	msg[13] = ((msg[13] << 35) | (msg[13] >> (64 - 35))) ^ msg[6]
	msg[4] += msg[9]
	msg[9] = ((msg[9] << 52) | (msg[9] >> (64 - 52))) ^ msg[4]
	msg[14] += msg[1]
	msg[1] = ((msg[1] << 23) | (msg[1] >> (64 - 23))) ^ msg[14]
	msg[8] += msg[5]
	msg[5] = ((msg[5] << 31) | (msg[5] >> (64 - 31))) ^ msg[8]
	msg[10] += msg[3]
	msg[3] = ((msg[3] << 37) | (msg[3] >> (64 - 37))) ^ msg[10]
	msg[12] += msg[7]
	msg[7] = ((msg[7] << 20) | (msg[7] >> (64 - 20))) ^ msg[12]
}

// the inverse of the last 4x16 mix operations
func mixLast1024Inv(msg *[16]uint64) {
	tmp := msg[7] ^ msg[12]
	msg[7] = (tmp >> 20) | (tmp << (64 - 20))
	msg[12] -= msg[7]
	tmp = msg[3] ^ msg[10]
	msg[3] = (tmp >> 37) | (tmp << (64 - 37))
	msg[10] -= msg[3]
	tmp = msg[5] ^ msg[8]
	msg[5] = (tmp >> 31) | (tmp << (64 - 31))
	msg[8] -= msg[5]
	tmp = msg[1] ^ msg[14]
	msg[1] = (tmp >> 23) | (tmp << (64 - 23))
	msg[14] -= msg[1]
	tmp = msg[9] ^ msg[4]
	msg[9] = (tmp >> 52) | (tmp << (64 - 52))
	msg[4] -= msg[9]
	tmp = msg[13] ^ msg[6]
	msg[13] = (tmp >> 35) | (tmp << (64 - 35))
	msg[6] -= msg[13]
	tmp = msg[11] ^ msg[2]
	msg[11] = (tmp >> 48) | (tmp << (64 - 48))
	msg[2] -= msg[11]
	tmp = msg[15] ^ msg[0]
	msg[15] = (tmp >> 9) | (tmp << (64 - 9))
	msg[0] -= msg[15]

	tmp = msg[9] ^ msg[10]
	msg[9] = (tmp >> 25) | (tmp << (64 - 25))
	msg[10] -= msg[9]
	tmp = msg[11] ^ msg[8]
	msg[11] = (tmp >> 44) | (tmp << (64 - 44))
	msg[8] -= msg[11]
	tmp = msg[13] ^ msg[14]
	msg[13] = (tmp >> 42) | (tmp << (64 - 42))
	msg[14] -= msg[13]
	tmp = msg[15] ^ msg[12]
	msg[15] = (tmp >> 19) | (tmp << (64 - 19))
	msg[12] -= msg[15]
	tmp = msg[1] ^ msg[6]
	msg[1] = (tmp >> 46) | (tmp << (64 - 46))
	msg[6] -= msg[1]
	tmp = msg[3] ^ msg[4]
	msg[3] = (tmp >> 47) | (tmp << (64 - 47))
	msg[4] -= msg[3]
	tmp = msg[5] ^ msg[2]
	msg[5] = (tmp >> 44) | (tmp << (64 - 44))
	msg[2] -= msg[5]
	tmp = msg[7] ^ msg[0]
	msg[7] = (tmp >> 31) | (tmp << (64 - 31))
	msg[0] -= msg[7]

	tmp = msg[1] ^ msg[8]
	msg[1] = (tmp >> 41) | (tmp << (64 - 41))
	msg[8] -= msg[1]
	tmp = msg[5] ^ msg[14]
	msg[5] = (tmp >> 42) | (tmp << (64 - 42))
	msg[14] -= msg[5]
	tmp = msg[3] ^ msg[12]
	msg[3] = (tmp >> 53) | (tmp << (64 - 53))
	msg[12] -= msg[3]
	tmp = msg[7] ^ msg[10]
	msg[7] = (tmp >> 4) | (tmp << (64 - 4))
	msg[10] -= msg[7]
	tmp = msg[15] ^ msg[4]
	msg[15] = (tmp >> 51) | (tmp << (64 - 51))
	msg[4] -= msg[15]
	tmp = msg[11] ^ msg[6]
	msg[11] = (tmp >> 56) | (tmp << (64 - 56))
	msg[6] -= msg[11]
	tmp = msg[13] ^ msg[2]
	msg[13] = (tmp >> 34) | (tmp << (64 - 34))
	msg[2] -= msg[13]
	tmp = msg[9] ^ msg[0]
	msg[9] = (tmp >> 16) | (tmp << (64 - 16))
	msg[0] -= msg[9]

	tmp = msg[15] ^ msg[14]
	msg[15] = (tmp >> 30) | (tmp << (64 - 30))
	msg[14] -= msg[15]
	tmp = msg[13] ^ msg[12]
	msg[13] = (tmp >> 44) | (tmp << (64 - 44))
	msg[12] -= msg[13]
	tmp = msg[11] ^ msg[10]
	msg[11] = (tmp >> 47) | (tmp << (64 - 47))
	msg[10] -= msg[11]
	tmp = msg[9] ^ msg[8]
	msg[9] = (tmp >> 12) | (tmp << (64 - 12))
	msg[8] -= msg[9]
	tmp = msg[7] ^ msg[6]
	msg[7] = (tmp >> 31) | (tmp << (64 - 31))
	msg[6] -= msg[7]
	tmp = msg[5] ^ msg[4]
	msg[5] = (tmp >> 37) | (tmp << (64 - 37))
	msg[4] -= msg[5]
	tmp = msg[3] ^ msg[2]
	msg[3] = (tmp >> 9) | (tmp << (64 - 9))
	msg[2] -= msg[3]
	tmp = msg[1] ^ msg[0]
	msg[1] = (tmp >> 41) | (tmp << (64 - 41))
	msg[0] -= msg[1]
}
