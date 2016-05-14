// Use of this source code is governed by a license
// that can be found in the LICENSE file

package skein

import (
	"github.com/EncEve/crypto/threefish"
)

// Update the hash with the given full blocks.
func skeinCore512(blocks []byte, hVal *[9]uint64, tweak *[3]uint64) {
	var message, msg [8]uint64
	var block [Size512]byte
	for i := 0; i < len(blocks); i += Size512 {
		// copy the message block into an array for
		// the toWords512 function
		copy(block[:], blocks[i:i+Size512])
		toWords512(&msg, &block)
		message = msg

		hVal[8] = threefish.C240 ^ hVal[0] ^ hVal[1] ^ hVal[2] ^
			hVal[3] ^ hVal[4] ^ hVal[5] ^ hVal[6] ^ hVal[7]

		incTweak(tweak, Size512)
		tweak[2] = tweak[0] ^ tweak[1]

		threefish.Encrypt512(hVal, tweak, &msg)
		xor512(hVal, &message, &msg)

		// clear the first block flag
		tweak[1] &^= firstBlock
	}
}

// Extract the output from the hash function
func skeinOutput512(dst *[Size512]byte, ctr uint64, hVal *[9]uint64) {
	var message, msg [8]uint64
	msg[0], message[0] = ctr, ctr

	hVal[8] = threefish.C240 ^ hVal[0] ^ hVal[1] ^ hVal[2] ^
		hVal[3] ^ hVal[4] ^ hVal[5] ^ hVal[6] ^ hVal[7]

	threefish.Encrypt512(hVal, &outTweak, &msg)
	xor512(hVal, &message, &msg)

	for i, v := range hVal[:8] {
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
func (s *skein512) finalize() {
	var message, msg [8]uint64
	// flush the buffer
	for i := s.off; i < Size512; i++ {
		s.buf[i] = 0
	}

	toWords512(&msg, &(s.buf))
	message = msg

	s.hVal[8] = threefish.C240 ^ s.hVal[0] ^ s.hVal[1] ^ s.hVal[2] ^
		s.hVal[3] ^ s.hVal[4] ^ s.hVal[5] ^ s.hVal[6] ^ s.hVal[7]

	incTweak(&(s.tweak), uint64(s.off))
	s.tweak[1] |= lastBlock // set the last block flag
	s.tweak[2] = s.tweak[0] ^ s.tweak[1]

	threefish.Encrypt512(&(s.hVal), &(s.tweak), &msg)
	xor512(&(s.hVal), &message, &msg)
	s.off = 0
}
