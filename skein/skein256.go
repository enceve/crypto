// Use of this source code is governed by a license
// that can be found in the LICENSE file

package skein

import "github.com/EncEve/crypto/threefish"

func (s *skein256) BlockSize() int { return Size256 }

func (s *skein256) Size() int { return s.hsize }

func (s *skein256) Reset() {
	s.off = 0
	s.msg = false
	copy(s.hVal[:4], s.initVal[:])
	s.tweak[0] = 0
	s.tweak[1] = messageParam<<56 | firstBlock
}

func (s *skein256) Write(in []byte) (int, error) {
	s.msg = true
	n := len(in)

	diff := Size256 - s.off
	if n > diff {
		// process buffer.
		copy(s.buf[s.off:], in[:diff])
		s.hashMessage(s.buf[:])
		s.off = 0

		in = in[diff:]
	}
	// process full blocks except for the last
	length := len(in)
	if length > Size256 {
		nn := length - (length % Size256)
		if nn == length {
			nn -= Size256
		}
		s.hashMessage(in[:nn])
		in = in[nn:]
	}
	s.off += copy(s.buf[s.off:], in)
	return n, nil
}

func (s *skein256) Sum(in []byte) []byte {
	s0 := *s // make a copy
	if s0.msg {
		s0.finalize()
	}

	var out [Size256]byte
	s0.output(&out, 0)
	return append(in, out[:s0.hsize]...)
}

// Update the hash with the given full blocks.
func (s *skein256) hashMessage(blocks []byte) {
	var message, msg [4]uint64
	var block [Size256]byte
	for i := 0; i < len(blocks); i += Size256 {
		// copy the message block into an array for
		// the toWords256 function
		copy(block[:], blocks[i:i+Size256])
		toWords256(&msg, &block)
		message = msg

		s.hVal[4] = threefish.C240 ^ s.hVal[0] ^ s.hVal[1] ^ s.hVal[2] ^ s.hVal[3]

		incTweak(&(s.tweak), Size256)
		s.tweak[2] = s.tweak[0] ^ s.tweak[1]

		threefish.Encrypt256(&(s.hVal), &(s.tweak), &msg)
		xor256(&(s.hVal), &message, &msg)

		// clear the first block flag
		s.tweak[1] &^= firstBlock
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

// Extract the output from the hash function
func (s *skein256) output(dst *[Size256]byte, ctr uint64) {
	var message, msg [4]uint64
	msg[0], message[0] = ctr, ctr

	s.hVal[4] = threefish.C240 ^ s.hVal[0] ^ s.hVal[1] ^ s.hVal[2] ^ s.hVal[3]

	threefish.Encrypt256(&(s.hVal), &outTweak, &msg)
	xor256(&(s.hVal), &message, &msg)

	for i, v := range s.hVal[:4] {
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

// Add a parameter (secret key, nonce etc.) to the hash function
func (s *skein256) addParam(ptype uint64, param []byte) {
	s.tweak[0] = 0
	s.tweak[1] = ptype<<56 | firstBlock
	s.Write(param)
	s.finalize()
}

// Add the configuration block to the hash function
func (s *skein256) addConfig(hashsize int) {
	var c [32]byte
	copy(c[:], schemaId)

	bits := uint64(hashsize * 8)
	c[8] = byte(bits)
	c[9] = byte(bits >> 8)
	c[10] = byte(bits >> 16)
	c[11] = byte(bits >> 24)
	c[12] = byte(bits >> 32)
	c[13] = byte(bits >> 40)
	c[14] = byte(bits >> 48)
	c[15] = byte(bits >> 56)

	s.addParam(configParam, c[:])
}
