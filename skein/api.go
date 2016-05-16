// Use of this source code is governed by a license
// that can be found in the LICENSE file

// Package skein implements the skein hash functions
// developed by Niels Ferguson, Stefan Lucks, Bruce Schneier,
// Doug Whiting, Mihir Bellare, Tadayoshi Kohno, Jon Callas,
// and Jesse Walker.
// Skein is based on the Threefish tweakable block cipher
// using Unique Block Iteration (UBI) chaining mode while
// leveraging an optional low-overhead argument-system
// for flexibility.
// Skein was submitted to the SHA-3 challenge.
//
// Skein Variants
//
// There are three skein variants all implemented by
// the skein package:
//     - Skein-256  has a state size of  256 bit (32 byte)
//     - Skein-512  has a state size of  512 bit (64 byte)
//     - Skein-1024 has a state size of 1024 bit (128 byte)
// The max. hash size of a skein variant is the same as
// the state size (block size), but skein can produce hash values of
// any length (limited by the state size).
package skein

import (
	"errors"
	"hash"
)

// Params contains the Skein configuration parameters.
// The BlockSize field is required and must be set
// to a valid value (32, 64, 128). If the HashSize
// is not set (or invalid), the default value, which
// is equal to the block size, is used. All other
// fields are optional  and can be nil.
type Params struct {
	BlockSize int    // Required: The block size of the skein variant (32 , 64 or 128)
	HashSize  int    // Optional: The hash size - valid are values between 1 and the block size (default is the block size)
	Key       []byte // Optional: The secret key for MAC
	PublicKey []byte // Optional: The public key for key-bound hashing
	KeyID     []byte // Optional: The key id for key derivation
	Nonce     []byte // Optional: The nonce for randomized hashing
}

// New returns a hash.Hash computing the Skein checksum.
// If the BlockSize parameter is invalid, an non-nil error
// is returned. If the HashSize parameter is not set (or invalid),
// the BlockSize is used as hash size.
func New(p *Params) (hash.Hash, error) {
	if p == nil {
		return nil, errors.New("Params argument must not be nil")
	}
	switch p.BlockSize {
	default:
		return nil, errors.New("invalid block size for skein")
	case Size256:
		s := new(skein256)
		s.initialize(p)
		return s, nil
	case Size512:
		s := new(skein512)
		s.initialize(p)
		return s, nil
	case Size1024:
		s := new(skein1024)
		s.initialize(p)
		return s, nil
	}
}

// New512 returns a hash.Hash computing the Skein-512 checksum.
// If the given size is not between 1 and 64 inclusively, the
// default hash size (64) is used.
func New512(size int) hash.Hash {
	s := new(skein512)
	if size < 1 || size > Size512 {
		s.hsize = Size512
	} else {
		s.hsize = size
	}

	switch s.hsize {
	default:
		s.addConfig(s.hsize)
		copy(s.initVal[:], s.hVal[:8])
	case 16:
		s.initVal = iv512_128
	case 20:
		s.initVal = iv512_160
	case 28:
		s.initVal = iv512_224
	case 32:
		s.initVal = iv512_256
	case 48:
		s.initVal = iv512_384
	case Size512:
		s.initVal = iv512_512
	}

	s.Reset()
	return s
}

// Sum512_256 computes the Skein-512 256 bit (32 byte) checksum of the msg.
func Sum512_256(msg []byte) [32]byte {
	s := New512(Size256)
	s.Write(msg)
	var out [32]byte
	s.Sum(out[:0])
	return out
}

// Sum512 computes the Skein-512 512 bit (64 byte) checksum of the msg.
func Sum512(msg []byte) [64]byte {
	s := New512(Size512)
	s.Write(msg)
	var out [64]byte
	s.Sum(out[:0])
	return out
}

// Sum computes the Skein checksum of the msg.
func Sum(msg []byte, p *Params) ([]byte, error) {
	s, err := New(p)
	if err != nil {
		return nil, err
	}
	s.Write(msg)
	return s.Sum(nil), nil
}

// The skein-256 hash function with a state size
// of 256 bit.
type skein256 struct {
	initVal [4]uint64
	hVal    [5]uint64
	tweak   [3]uint64
	buf     [Size256]byte
	off     int
	hsize   int
	msg     bool
}

func (s *skein256) BlockSize() int { return Size256 }

func (s *skein256) Size() int { return s.hsize }

func (s *skein256) Reset() {
	s.off = 0
	s.msg = false
	copy(s.hVal[:4], s.initVal[:])
	for i := range s.buf {
		s.buf[i] = 0
	}
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
		skeinCore256(s.buf[:], &(s.hVal), &(s.tweak))
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
		skeinCore256(in[:nn], &(s.hVal), &(s.tweak))
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
	skeinOutput256(&out, 0, &(s0.hVal))
	return append(in, out[:s0.hsize]...)
}

// sein-512 hash function with a state size
// of 512 bit. Skein-512 is recommended by the
// skein authors for most use cases.
type skein512 struct {
	initVal [8]uint64
	hVal    [9]uint64
	tweak   [3]uint64
	buf     [Size512]byte
	off     int
	hsize   int
	msg     bool
}

func (s *skein512) BlockSize() int { return Size512 }

func (s *skein512) Size() int { return s.hsize }

func (s *skein512) Reset() {
	s.off = 0
	s.msg = false
	copy(s.hVal[:8], s.initVal[:])
	for i := range s.buf {
		s.buf[i] = 0
	}
	s.tweak[0] = 0
	s.tweak[1] = messageParam<<56 | firstBlock
}

func (s *skein512) Write(in []byte) (int, error) {
	n := len(in)

	diff := Size512 - s.off
	if n > diff {
		// process buffer.
		copy(s.buf[s.off:], in[:diff])
		skeinCore512(s.buf[:], &(s.hVal), &(s.tweak))
		s.off = 0

		in = in[diff:]
	}
	// process full blocks except for the last
	length := len(in)
	if length > Size512 {
		nn := length - (length % Size512)
		if nn == length {
			nn -= Size512
		}
		skeinCore512(in[:nn], &(s.hVal), &(s.tweak))
		in = in[nn:]
	}
	s.off += copy(s.buf[s.off:], in)

	s.msg = true
	return n, nil
}

func (s *skein512) Sum(in []byte) []byte {
	s0 := *s // make a copy
	if s0.msg {
		s0.finalize()
	}

	var out [Size512]byte
	skeinOutput512(&out, 0, &(s0.hVal))
	return append(in, out[:s0.hsize]...)
}

// The skein-1024 hash function with a state size
// of 1024 bit.
// Skein-1024 is the very conservative skein variant.
type skein1024 struct {
	initVal [16]uint64
	hVal    [17]uint64
	tweak   [3]uint64
	buf     [Size1024]byte
	off     int
	hsize   int
	msg     bool
}

func (s *skein1024) BlockSize() int { return Size1024 }

func (s *skein1024) Size() int { return s.hsize }

func (s *skein1024) Reset() {
	s.off = 0
	s.msg = false
	copy(s.hVal[:16], s.initVal[:])
	for i := range s.buf {
		s.buf[i] = 0
	}
	s.tweak[0] = 0
	s.tweak[1] = messageParam<<56 | firstBlock
}

func (s *skein1024) Write(in []byte) (int, error) {
	s.msg = true
	n := len(in)

	diff := Size1024 - s.off
	if n > diff {
		// process buffer.
		copy(s.buf[s.off:], in[:diff])
		skeinCore1024(s.buf[:], &(s.hVal), &(s.tweak))
		s.off = 0

		in = in[diff:]
	}
	// process full blocks except for the last
	length := len(in)
	if length > Size1024 {
		nn := length - (length % Size1024)
		if nn == length {
			nn -= Size1024
		}
		skeinCore1024(in[:nn], &(s.hVal), &(s.tweak))
		in = in[nn:]
	}
	s.off += copy(s.buf[s.off:], in)
	return n, nil
}

func (s *skein1024) Sum(in []byte) []byte {
	s0 := *s
	if s0.msg {
		s0.finalize()
	}

	var out [Size1024]byte
	skeinOutput1024(&out, 0, &(s0.hVal))
	return append(in, out[:s0.hsize]...)
}
