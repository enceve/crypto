// Use of this source code is governed by a license
// that can be found in the LICENSE file

package skein

import "github.com/enceve/crypto/threefish"

// Update the hash with the given full blocks.
func skeinCore256(blocks []byte, hVal *[5]uint64, tweak *[3]uint64) {
	var message, msg [4]uint64
	var block [Size256]byte
	for i := 0; i < len(blocks); i += Size256 {
		// copy the message block into an array for
		// the toWords256 function
		copy(block[:], blocks[i:i+Size256])
		toWords256(&msg, &block)
		message = msg

		hVal[4] = threefish.C240 ^ hVal[0] ^ hVal[1] ^ hVal[2] ^ hVal[3]

		incTweak(tweak, Size256)
		tweak[2] = tweak[0] ^ tweak[1]

		threefish.Encrypt256(hVal, tweak, &msg)
		xor256(hVal, &message, &msg)

		// clear the first block flag
		tweak[1] &^= firstBlock
	}
}

// Extract the output from the hash function
func skeinOutput256(dst *[Size256]byte, ctr uint64, hVal *[5]uint64) {
	var message, msg [4]uint64
	msg[0], message[0] = ctr, ctr

	hVal[4] = threefish.C240 ^ hVal[0] ^ hVal[1] ^ hVal[2] ^ hVal[3]

	threefish.Encrypt256(hVal, &outTweak, &msg)
	xor256(hVal, &message, &msg)

	for i, v := range hVal[:4] {
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
func (s *skein256) finalize() {
	var message, msg [4]uint64
	// flush the buffer
	for i := s.off; i < len(s.buf); i++ {
		s.buf[i] = 0
	}

	toWords256(&msg, &(s.buf))
	message = msg

	s.hVal[4] = threefish.C240 ^ s.hVal[0] ^ s.hVal[1] ^ s.hVal[2] ^ s.hVal[3]

	incTweak(&(s.tweak), uint64(s.off))
	s.tweak[1] |= lastBlock // set the last block flag
	s.tweak[2] = s.tweak[0] ^ s.tweak[1]

	threefish.Encrypt256(&(s.hVal), &(s.tweak), &msg)
	xor256(&(s.hVal), &message, &msg)
	s.off = 0
}
