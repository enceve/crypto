// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package threefish

// Encrypt256 does a threefish-256 encryption operation
// using the expanded 256 bit key (sk), the 128 bit tweak and
// the 256 bit block (msg).
// The sk[4] must be sk[0] xor sk[1] xor ... sk[3] xor C240
// The tweak[2] must be tweak[0] xor tweak[1]
func Encrypt256(sk *[5]uint64, tweak *[3]uint64, msg *[4]uint64) {
	addKey256(sk, tweak, msg, 0)
	mixFirst256(msg)
	addKey256(sk, tweak, msg, 1)
	mixLast256(msg)

	addKey256(sk, tweak, msg, 2)
	mixFirst256(msg)
	addKey256(sk, tweak, msg, 3)
	mixLast256(msg)

	addKey256(sk, tweak, msg, 4)
	mixFirst256(msg)
	addKey256(sk, tweak, msg, 5)
	mixLast256(msg)

	addKey256(sk, tweak, msg, 6)
	mixFirst256(msg)
	addKey256(sk, tweak, msg, 7)
	mixLast256(msg)

	addKey256(sk, tweak, msg, 8)
	mixFirst256(msg)
	addKey256(sk, tweak, msg, 9)
	mixLast256(msg)

	addKey256(sk, tweak, msg, 10)
	mixFirst256(msg)
	addKey256(sk, tweak, msg, 11)
	mixLast256(msg)

	addKey256(sk, tweak, msg, 12)
	mixFirst256(msg)
	addKey256(sk, tweak, msg, 13)
	mixLast256(msg)

	addKey256(sk, tweak, msg, 14)
	mixFirst256(msg)
	addKey256(sk, tweak, msg, 15)
	mixLast256(msg)

	addKey256(sk, tweak, msg, 16)
	mixFirst256(msg)
	addKey256(sk, tweak, msg, 17)
	mixLast256(msg)

	addKey256(sk, tweak, msg, 18)
}

// Decrypt256 does a threefish-256 decryption operation
// using the expanded 256 bit key (sk), the 128 bit tweak and
// the 256 bit block (msg).
// The sk[4] must be sk[0] xor sk[1] xor ... sk[3] xor C240
// The tweak[2] must be tweak[0] xor tweak[1]
func Decrypt256(sk *[5]uint64, tweak *[3]uint64, msg *[4]uint64) {
	subKey256(sk, tweak, msg, 18)
	mixLast256Inv(msg)
	subKey256(sk, tweak, msg, 17)
	mixFirst256Inv(msg)

	subKey256(sk, tweak, msg, 16)
	mixLast256Inv(msg)
	subKey256(sk, tweak, msg, 15)
	mixFirst256Inv(msg)

	subKey256(sk, tweak, msg, 14)
	mixLast256Inv(msg)
	subKey256(sk, tweak, msg, 13)
	mixFirst256Inv(msg)

	subKey256(sk, tweak, msg, 12)
	mixLast256Inv(msg)
	subKey256(sk, tweak, msg, 11)
	mixFirst256Inv(msg)

	subKey256(sk, tweak, msg, 10)
	mixLast256Inv(msg)
	subKey256(sk, tweak, msg, 9)
	mixFirst256Inv(msg)

	subKey256(sk, tweak, msg, 8)
	mixLast256Inv(msg)
	subKey256(sk, tweak, msg, 7)
	mixFirst256Inv(msg)

	subKey256(sk, tweak, msg, 6)
	mixLast256Inv(msg)
	subKey256(sk, tweak, msg, 5)
	mixFirst256Inv(msg)

	subKey256(sk, tweak, msg, 4)
	mixLast256Inv(msg)
	subKey256(sk, tweak, msg, 3)
	mixFirst256Inv(msg)

	subKey256(sk, tweak, msg, 2)
	mixLast256Inv(msg)
	subKey256(sk, tweak, msg, 1)
	mixFirst256Inv(msg)

	subKey256(sk, tweak, msg, 0)
}

// adds the 256 bit key and the 128 bit tweak
// with the message block
// the added key and tweak depends on the round
func addKey256(sk *[5]uint64, tweak *[3]uint64, msg *[4]uint64, r int) {
	msg[0] += sk[(r)%5]
	msg[1] += sk[(r+1)%5] + tweak[r%3]
	msg[2] += sk[(r+2)%5] + tweak[(r+1)%3]
	msg[3] += sk[(r+3)%5] + uint64(r)
}

// subs the 256 bit key and the 128 bit tweak
// from the message block
// the subtracted key and tweak depends on the round
func subKey256(sk *[5]uint64, tweak *[3]uint64, msg *[4]uint64, r int) {
	msg[0] -= sk[(r)%5]
	msg[1] -= sk[(r+1)%5] + tweak[r%3]
	msg[2] -= sk[(r+2)%5] + tweak[(r+1)%3]
	msg[3] -= sk[(r+3)%5] + uint64(r)
}

// the first 4x4 mix operations
func mixFirst256(msg *[4]uint64) {
	msg[0] += msg[1]
	msg[1] = ((msg[1] << 14) | (msg[1] >> (64 - 14))) ^ msg[0]
	msg[2] += msg[3]
	msg[3] = ((msg[3] << 16) | (msg[3] >> (64 - 16))) ^ msg[2]

	msg[0] += msg[3]
	msg[3] = ((msg[3] << 52) | (msg[3] >> (64 - 52))) ^ msg[0]
	msg[2] += msg[1]
	msg[1] = ((msg[1] << 57) | (msg[1] >> (64 - 57))) ^ msg[2]

	msg[0] += msg[1]
	msg[1] = ((msg[1] << 23) | (msg[1] >> (64 - 23))) ^ msg[0]
	msg[2] += msg[3]
	msg[3] = ((msg[3] << 40) | (msg[3] >> (64 - 40))) ^ msg[2]

	msg[0] += msg[3]
	msg[3] = ((msg[3] << 5) | (msg[3] >> (64 - 5))) ^ msg[0]
	msg[2] += msg[1]
	msg[1] = ((msg[1] << 37) | (msg[1] >> (64 - 37))) ^ msg[2]
}

// the inverse of the first 4x4 mix operations
func mixFirst256Inv(msg *[4]uint64) {
	tmp := msg[1] ^ msg[2]
	msg[1] = (tmp >> 37) | (tmp << (64 - 37))
	msg[2] -= msg[1]
	tmp = msg[3] ^ msg[0]
	msg[3] = (tmp >> 5) | (tmp << (64 - 5))
	msg[0] -= msg[3]

	tmp = msg[3] ^ msg[2]
	msg[3] = (tmp >> 40) | (tmp << (64 - 40))
	msg[2] -= msg[3]
	tmp = msg[1] ^ msg[0]
	msg[1] = (tmp >> 23) | (tmp << (64 - 23))
	msg[0] -= msg[1]

	tmp = msg[1] ^ msg[2]
	msg[1] = (tmp >> 57) | (tmp << (64 - 57))
	msg[2] -= msg[1]
	tmp = msg[3] ^ msg[0]
	msg[3] = (tmp >> 52) | (tmp << (64 - 52))
	msg[0] -= msg[3]

	tmp = msg[3] ^ msg[2]
	msg[3] = (tmp >> 16) | (tmp << (64 - 16))
	msg[2] -= msg[3]
	tmp = msg[1] ^ msg[0]
	msg[1] = (tmp >> 14) | (tmp << (64 - 14))
	msg[0] -= msg[1]
}

// the last 4x4 mix operations
func mixLast256(msg *[4]uint64) {
	msg[0] += msg[1]
	msg[1] = ((msg[1] << 25) | (msg[1] >> (64 - 25))) ^ msg[0]
	msg[2] += msg[3]
	msg[3] = ((msg[3] << 33) | (msg[3] >> (64 - 33))) ^ msg[2]

	msg[0] += msg[3]
	msg[3] = ((msg[3] << 46) | (msg[3] >> (64 - 46))) ^ msg[0]
	msg[2] += msg[1]
	msg[1] = ((msg[1] << 12) | (msg[1] >> (64 - 12))) ^ msg[2]

	msg[0] += msg[1]
	msg[1] = ((msg[1] << 58) | (msg[1] >> (64 - 58))) ^ msg[0]
	msg[2] += msg[3]
	msg[3] = ((msg[3] << 22) | (msg[3] >> (64 - 22))) ^ msg[2]

	msg[0] += msg[3]
	msg[3] = ((msg[3] << 32) | (msg[3] >> (64 - 32))) ^ msg[0]
	msg[2] += msg[1]
	msg[1] = ((msg[1] << 32) | (msg[1] >> (64 - 32))) ^ msg[2]
}

// the inverse of the last 4x4 mix operations
func mixLast256Inv(msg *[4]uint64) {
	tmp := msg[1] ^ msg[2]
	msg[1] = (tmp >> 32) | (tmp << (64 - 32))
	msg[2] -= msg[1]
	tmp = msg[3] ^ msg[0]
	msg[3] = (tmp >> 32) | (tmp << (64 - 32))
	msg[0] -= msg[3]

	tmp = msg[3] ^ msg[2]
	msg[3] = (tmp >> 22) | (tmp << (64 - 22))
	msg[2] -= msg[3]
	tmp = msg[1] ^ msg[0]
	msg[1] = (tmp >> 58) | (tmp << (64 - 58))
	msg[0] -= msg[1]

	tmp = msg[1] ^ msg[2]
	msg[1] = (tmp >> 12) | (tmp << (64 - 12))
	msg[2] -= msg[1]
	tmp = msg[3] ^ msg[0]
	msg[3] = (tmp >> 46) | (tmp << (64 - 46))
	msg[0] -= msg[3]

	tmp = msg[3] ^ msg[2]
	msg[3] = (tmp >> 33) | (tmp << (64 - 33))
	msg[2] -= msg[3]
	tmp = msg[1] ^ msg[0]
	msg[1] = (tmp >> 25) | (tmp << (64 - 25))
	msg[0] -= msg[1]
}
