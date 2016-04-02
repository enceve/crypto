// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The blake2b package implements the blake2b hash function
// based on the RFC 7693 (https://tools.ietf.org/html/rfc7693).
// Blake2b is the 64 bit version of the blake2 hash function
// and supports hash values from 8 to 512 bit (1 to 64 byte).
// The package API directly supports 160, 256, 384 and 512 bit
// hash values, but custom sizes can be used as well.
// Furthermore blake2b can be used for:
// 		- simple, randomized and personalized hashing
//		- MACs (builtin)
//		- tree hashing
// This package supports:
//	- simple and randomized hashing
//	- MACs
// Personalization and Tree-hashing are not supported.
package blake2b

import (
	"encoding/binary"
	"errors"
	"hash"
)

// the blake2b hash struct
type blake2b struct {
	hVal [8]uint64       // the chain values
	ctr  [2]uint64       // the counter (max 2^128 bytes)
	f    uint64          // the final block flag
	buf  [BlockSize]byte // the buffer
	off  int             // the buffer offset

	initVal [8]uint64       // initial chain values
	keyed   bool            // flag whether a key is used (MAC)
	key     [BlockSize]byte // the key for MAC
	hsize   int             // the hash size in bytes
}

// The parameters for configuring the blake2b hash function.
// All values are optional. If the HashSize is not between 1
// and 64 inclusively, it will be set to the default value.
type Params struct {
	HashSize int    // The hash size of blake2b in bytes (default and max. is 64)
	Key      []byte // The key for MAC (length must between 0 and 64)
	Salt     []byte // The salt (length must between 0 and 16)
}

func verifyParams(p *Params) error {
	if p.HashSize < 1 || p.HashSize > Size {
		p.HashSize = Size
	}
	if len(p.Key) > keySize {
		return errors.New("key is too large")
	}
	if len(p.Salt) > saltSize {
		return errors.New("salt is too large")
	}
	return nil
}

// predefined parameters for the common hash sizes 256 and 512 bit
var (
	params512 *Params = &Params{HashSize: Size}
	params256 *Params = &Params{HashSize: 32}
)

// Sum512 returns the 512 bit blake2b checksum of the msg.
func Sum512(msg []byte) []byte {
	h := new(blake2b)
	h.initialize(params512)
	h.Write(msg)
	return h.Sum(nil)
}

// Sum256 returns the 256 bit blake2b checksum of the msg.
func Sum256(msg []byte) []byte {
	h := new(blake2b)
	h.initialize(params256)
	h.Write(msg)
	return h.Sum(nil)
}

// Sum returns the blake2b checksum of the msg.
// The Params argument specifies the blake2b configuration
// and if it's not valid a non-nil error is returned.
func Sum(msg []byte, p *Params) ([]byte, error) {
	h, err := New(p)
	if err != nil {
		return nil, err
	}
	h.Write(msg)
	return h.Sum(nil), nil
}

// Returns a new hash.Hash computing the blake2b checksum.
// The Params argument must not be nil and must contain valid
// parameters.
func New(p *Params) (hash.Hash, error) {
	if p == nil {
		return nil, errors.New("p argument must not be nil")
	}
	if err := verifyParams(p); err != nil {
		return nil, err
	}
	b := new(blake2b)
	b.initialize(p)
	return b, nil
}

func (h *blake2b) BlockSize() int { return BlockSize }

func (h *blake2b) Size() int { return h.hsize }

func (h *blake2b) Write(src []byte) (int, error) {
	n := len(src)
	in := src

	diff := BlockSize - int(h.off)
	if n > diff {
		// process buffer.
		copy(h.buf[h.off:], in[:diff])
		update(&(h.hVal), &(h.ctr), h.f, h.buf[:])
		h.off = 0

		in = in[diff:]
	}
	// process full blocks except for the last
	length := len(in)
	if length > BlockSize {
		nn := length - (length % BlockSize)
		if nn == length {
			nn -= BlockSize
		}
		update(&(h.hVal), &(h.ctr), h.f, in[:nn])
		in = in[nn:]
	}
	h.off += copy(h.buf[h.off:], in)
	return n, nil
}

func (h *blake2b) Reset() {
	h.hVal = h.initVal
	h.ctr[0], h.ctr[1] = 0, 0
	h.f = 0
	for i := range h.buf {
		h.buf[i] = 0
	}
	h.off = 0
	if h.keyed {
		h.Write(h.key[:])
	}
}

func (h *blake2b) Sum(b []byte) []byte {
	h0 := *h
	var out [Size]byte
	h0.finalize(&out)
	return append(b, out[:h0.hsize]...)
}

// Finalize the hash by adding padding bytes (if necessary)
// and extract the hash to a byte array.
func (h *blake2b) finalize(out *[Size]byte) {
	// sub the padding length form the counter
	diff := BlockSize - uint64(h.off)
	if h.ctr[0] < diff {
		h.ctr[1]--
	}
	h.ctr[0] -= diff

	// pad the buffer
	for i := h.off; i < BlockSize; i++ {
		h.buf[i] = 0
	}
	// set the last block flag
	h.f = uint64(0xffffffffffffffff)

	// process last block
	update(&(h.hVal), &(h.ctr), h.f, h.buf[:])

	// extract hash
	j := 0
	for _, s := range h.hVal {
		out[j+0] = byte(s >> 0)
		out[j+1] = byte(s >> 8)
		out[j+2] = byte(s >> 16)
		out[j+3] = byte(s >> 24)
		out[j+4] = byte(s >> 32)
		out[j+5] = byte(s >> 40)
		out[j+6] = byte(s >> 48)
		out[j+7] = byte(s >> 56)
		j += 8
	}
}

// Initialize the hash function with the given
// parameters
func (h *blake2b) initialize(conf *Params) {
	// create parameter block.
	var p [BlockSize]byte
	p[0] = byte(conf.HashSize)
	p[1] = uint8(len(conf.Key))
	p[2] = 1
	p[3] = 1
	if conf.Salt != nil {
		copy(p[32:], conf.Salt)
	}

	// initialize hash values
	h.hsize = conf.HashSize
	for i := range iv {
		h.hVal[i] = iv[i] ^ binary.LittleEndian.Uint64(p[i*8:])
	}

	// process key
	if conf.Key != nil {
		copy(h.key[:], conf.Key)
		h.Write(h.key[:])
		h.keyed = true
	}

	// save the initialized state.
	h.initVal = h.hVal
}
