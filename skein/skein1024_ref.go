// Use of this source code is governed by a license
// that can be found in the LICENSE file

package skein

import "github.com/enceve/crypto/threefish"

// Update the hash with the given full blocks.
func skeinCore1024(blocks []byte, hVal *[17]uint64, tweak *[3]uint64) {
	var message, msg [16]uint64
	var block [Size1024]byte
	for i := 0; i < len(blocks); i += Size1024 {
		// copy the message block into an array for
		// the toWords1024 function
		copy(block[:], blocks[i:i+Size1024])
		toWords1024(&msg, &block)
		message = msg

		hVal[16] = threefish.C240 ^ hVal[0] ^ hVal[1] ^ hVal[2] ^ hVal[3] ^
			hVal[4] ^ hVal[5] ^ hVal[6] ^ hVal[7] ^ hVal[8] ^ hVal[9] ^
			hVal[10] ^ hVal[11] ^ hVal[12] ^ hVal[13] ^ hVal[14] ^ hVal[15]

		incTweak(tweak, Size1024)
		tweak[2] = tweak[0] ^ tweak[1]

		threefish.Encrypt1024(hVal, tweak, &msg)
		xor1024(hVal, &message, &msg)

		// clear the first block flag
		tweak[1] &^= firstBlock
	}
}

// Extract the output from the hash function
func skeinOutput1024(dst *[Size1024]byte, ctr uint64, hVal *[17]uint64) {
	var message, msg [16]uint64
	msg[0], message[0] = ctr, ctr

	hVal[16] = threefish.C240 ^ hVal[0] ^ hVal[1] ^ hVal[2] ^ hVal[3] ^
		hVal[4] ^ hVal[5] ^ hVal[6] ^ hVal[7] ^ hVal[8] ^ hVal[9] ^
		hVal[10] ^ hVal[11] ^ hVal[12] ^ hVal[13] ^ hVal[14] ^ hVal[15]

	threefish.Encrypt1024(hVal, &outTweak, &msg)
	xor1024(hVal, &message, &msg)

	for i, v := range hVal[:16] {
		j := i * 8
		dst[j+0] = byte(v)
		dst[j+1] = byte(v >> 8)
		dst[j+2] = byte(v >> 16)
		dst[j+3] = byte(v >> 24)
		dst[j+4] = byte(v >> 32)
		dst[j+5] = byte(v >> 40)
		dst[j+6] = byte(v >> 48)
		dst[j+7] = byte(v >> 56)
	}
}

// Finalize the hash function with the last message block
func (s *skein1024) finalize() {
	var message, msg [16]uint64
	// flush the buffer
	for i := s.off; i < len(s.buf); i++ {
		s.buf[i] = 0
	}

	toWords1024(&msg, &s.buf)
	message = msg

	s.hVal[16] = threefish.C240 ^ s.hVal[0] ^ s.hVal[1] ^ s.hVal[2] ^ s.hVal[3] ^
		s.hVal[4] ^ s.hVal[5] ^ s.hVal[6] ^ s.hVal[7] ^ s.hVal[8] ^ s.hVal[9] ^
		s.hVal[10] ^ s.hVal[11] ^ s.hVal[12] ^ s.hVal[13] ^ s.hVal[14] ^ s.hVal[15]

	incTweak(&(s.tweak), uint64(s.off))
	s.tweak[1] |= lastBlock // set the last block flag
	s.tweak[2] = s.tweak[0] ^ s.tweak[1]

	threefish.Encrypt1024(&(s.hVal), &(s.tweak), &msg)
	xor1024(&(s.hVal), &message, &msg)
	s.off = 0
}
