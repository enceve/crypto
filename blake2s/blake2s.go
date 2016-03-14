// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The blake2s package implements the blake2s hash function.
// Blake2s is the 32 bit version of the blake2 hash function
// and supports hash values from 8 to 256 bit (1 to 32 byte).
// The package API directly supports 128, 160, 224 and 256 bit
// hash values, but custom sizes can be used as well.
// Furthermore blake2s can be used for:
// 		- simple, randomized and personalized hashing
//		- MACs (builtin)
//		- tree hashing
// This package supports:
//	    - simple and randomized hashing
//		- MACs
// Personalization and Tree-hashing are not supported.
package blake2s

import (
	"encoding/binary"
	"errors"
	"hash"
)

// the blake2s hash struct
type blake2s struct {
	hVal [8]uint32       // the chain values
	ctr  [2]uint32       // the counter (max 2^64 bytes)
	f    uint32          // the final block flag
	buf  [BlockSize]byte // the buffer
	off  int             // the buffer offset

	initVal [8]uint32       // initial chain values
	keyed   bool            // flag whether a key is used (MAC)
	key     [BlockSize]byte // the key for MAC
	hsize   int             // the hash size in bytes
}

// The parameters for configuring the blake2s hash function.
// All values are optional.
type Params struct {
	HashSize int    // The hash size of blake2s in bytes (default and max. is 32)
	Key      []byte // The key for MAC (padded with zeros)
	Salt     []byte // The salt (if < 8 bytes, padded with zeros)
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

// predefined parameters for the common hash sizes 128, 160, 224 and 256 bit
var (
	params256 *Params = &Params{HashSize: HashSize}
	params224 *Params = &Params{HashSize: 28}
	params160 *Params = &Params{HashSize: 20}
	params128 *Params = &Params{HashSize: 16}
)

// Creates a new blake2b hash function from the given
// parameters. If the parameter argument is nil, or
// parameters are invalid, an error nonnil is returned.
func New(p *Params) (hash.Hash, error) {
	if p == nil {
		return nil, errors.New("parameter arg must not be nil")
	} else {
		if p.HashSize == 0 {
			p.HashSize = HashSize
		}
		if err := verifyParams(p); err != nil {
			return nil, err
		}
	}

	b := new(blake2s)
	b.initialize(p)
	return b, nil
}

// Creates a new blake2s hash function for
// 256 bit hash values.
func New256() hash.Hash {
	b := new(blake2s)
	b.initialize(params256)
	return b
}

// Creates a new blake2s hash function for
// 224 bit hash values.
func New224() hash.Hash {
	b := new(blake2s)
	b.initialize(params224)
	return b
}

// Creates a new blake2s hash function for
// 160 bit hash values.
func New160() hash.Hash {
	b := new(blake2s)
	b.initialize(params160)
	return b
}

// Creates a new blake2s hash function for
// 128 bit hash values.
func New128() hash.Hash {
	b := new(blake2s)
	b.initialize(params128)
	return b
}

// Creates a new blake2s hash function configured
// as a MAC with the given key. The size argument
// specifies the size of the MAC in bytes. If the
// length of the key is greater than the max. key
// size or the size argument is greater than the
// max. hash size, this function returns a nonnil
// error
func NewMAC(size int, key []byte) (hash.Hash, error) {
	h, err := New(&Params{HashSize: size, Key: key})
	return h, err
}

// Returns the block size of blake2s in bytes.
func (h *blake2s) BlockSize() int { return BlockSize }

// Returns the hash size of blake2b in bytes wich
// is between 1 and 32.
func (b *blake2s) Size() int { return b.hsize }

// Write (via the embedded io.Writer interface) adds more
// data to the running hash. It never returns an error.
func (h *blake2s) Write(src []byte) (int, error) {
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
func (h *blake2s) Reset() {
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
func (h *blake2s) Sum(b []byte) []byte {
	h0 := *h
	var out [HashSize]byte
	h0.finalize(&out)
	return append(b, out[:h0.hsize]...)
}

// Finalize the hash by adding padding bytes (if necessary)
// and extract the hash to a byte array.
func (h *blake2s) finalize(out *[HashSize]byte) {
	// sub the padding length form the counter
	diff := BlockSize - uint32(h.off)
	if h.ctr[0] < diff {
		h.ctr[1]--
	}
	h.ctr[0] -= diff

	// pad the buffer
	for i := h.off; i < BlockSize; i++ {
		h.buf[i] = 0
	}
	// set the last block flag
	h.f = uint32(0xffffffff)

	// process last block
	update(&(h.hVal), &(h.ctr), h.f, h.buf[:])

	// extract hash
	j := 0
	for _, s := range h.hVal {
		out[j+0] = byte(s >> 0)
		out[j+1] = byte(s >> 8)
		out[j+2] = byte(s >> 16)
		out[j+3] = byte(s >> 24)
		j += 4
	}
}

// Initialize the hash function with the given
// parameters
func (h *blake2s) initialize(conf *Params) {
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
		h.hVal[i] = iv[i] ^ binary.LittleEndian.Uint32(p[i*4:])
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
