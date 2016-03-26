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
// All values are optional.
type Params struct {
	HashSize int    // The hash size of blake2b in bytes (default and max. is 64)
	Key      []byte // The key for MAC (padded with zeros)
	Salt     []byte // The salt (if < 16 bytes, padded with zeros)
}

func verifyParams(p *Params) error {
	if p.HashSize > HashSize {
		return errors.New("hash size is too large")
	}
	if p.HashSize < 1 {
		return errors.New("hash size is too small")
	}
	if len(p.Key) > KeySize {
		return errors.New("key is too large")
	}
	if len(p.Salt) > SaltSize {
		return errors.New("salt is too large")
	}
	return nil
}

// predefined parameters for the common hash sizes 160, 256, 384 and 512 bit
var (
	params512 *Params = &Params{HashSize: HashSize}
	params384 *Params = &Params{HashSize: 48}
	params256 *Params = &Params{HashSize: 32}
	params160 *Params = &Params{HashSize: 20}
)

// Creates a new blake2b hash function from the given
// parameters. If the parameter argument is nil, or
// parameters are invalid, an error non-nil is returned.
func New(p *Params) (hash.Hash, error) {
	if p == nil {
		return nil, errors.New("p argument must not be nil")
	} else {
		if p.HashSize == 0 {
			p.HashSize = HashSize
		}
		if err := verifyParams(p); err != nil {
			return nil, err
		}
	}

	b := new(blake2b)
	b.initialize(p)
	return b, nil
}

// Creates a new blake2b hash function for
// 512 bit hash values.
func New512() hash.Hash {
	b := new(blake2b)
	b.initialize(params512)
	return b
}

// Creates a new blake2b hash function for
// 384 bit hash values.
func New384() hash.Hash {
	b := new(blake2b)
	b.initialize(params384)
	return b
}

// Creates a new blake2b hash function for
// 256 bit hash values.
func New256() hash.Hash {
	b := new(blake2b)
	b.initialize(params256)
	return b
}

// Creates a new blake2b hash function for
// 160 bit hash values.
func New160() hash.Hash {
	b := new(blake2b)
	b.initialize(params160)
	return b
}

// Creates a new blake2b hash function configured
// as a MAC with the given key. The size argument
// specifies the size of the MAC in bytes. If the
// length of the key is greater than the max. key
// size or the size argument is greater than the
// max. hash size, this function returns a non-nil
// error
func NewMAC(size int, key []byte) (hash.Hash, error) {
	h, err := New(&Params{HashSize: size, Key: key})
	return h, err
}

// Returns the block size of blake2b in bytes.
func (h *blake2b) BlockSize() int { return BlockSize }

// Returns the hash size of blake2b in bytes wich
// is between 1 and 64.
func (h *blake2b) Size() int { return h.hsize }

// Write (via the embedded io.Writer interface) adds more
// data to the running hash. It never returns an error.
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

// Reset resets the Hash to its initial state.
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

// Sum appends the current hash to b and returns the resulting slice.
// It does not change the underlying hash state.
func (h *blake2b) Sum(b []byte) []byte {
	h0 := *h
	var out [HashSize]byte
	h0.finalize(&out)
	return append(b, out[:h0.hsize]...)
}

// Finalize the hash by adding padding bytes (if necessary)
// and extract the hash to a byte array.
func (h *blake2b) finalize(out *[HashSize]byte) {
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
