// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The blake2s package implements the blake2s hash function.
// Blake2s is the 32 bit version of the blake2 hash function
// and supports hash values from 8 to 256 bit (1 to 32 byte).
// The package API directly supports 160 and 256 bit
// hash values, but custom sizes can be used as well.
// Furthermore blake2s supports randomized hashing and can be
// used as a MAC.
package blake2s

import (
	"errors"
	"hash"
)

// the blake2s hash struct
type blake2s struct {
	hVal [8]uint32       // the chain values
	ctr  [2]uint32       // the counter (max 2^64 bytes)
	buf  [BlockSize]byte // the buffer
	off  int             // the buffer offset

	initVal [8]uint32       // initial chain values
	keyed   bool            // flag whether a key is used (MAC)
	key     [BlockSize]byte // the key for MAC
	hsize   int             // the hash size in bytes
}

// The parameters for configuring the blake2s hash function.
// All values are optional. If the HashSize is not between 1
// and 32 inclusively, it will be set to the default value.
type Params struct {
	HashSize int    // The hash size of blake2s in bytes (default and max. is 32)
	Key      []byte // The key for MAC (length must between 0 and 32)
	Salt     []byte // The salt (length must between 0 and 8)
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

// predefined parameters for the common hash sizes 160 and 256 bit
var (
	params256 *Params = &Params{HashSize: Size}
	params160 *Params = &Params{HashSize: 20}
)

// Sum256 returns the 256 bit blake2s checksum of the msg.
func Sum256(msg []byte) []byte {
	h := new(blake2s)
	h.initialize(params256)
	h.Write(msg)
	return h.Sum(nil)
}

// Sum160 returns the 160 bit blake2s checksum of the msg.
func Sum160(msg []byte) []byte {
	h := new(blake2s)
	h.initialize(params160)
	h.Write(msg)
	return h.Sum(nil)
}

// Sum returns the blake2s checksum of the msg.
// The Params argument specifies the blake2s configuration
// and if it's not valid a non-nil error is returned.
func Sum(msg []byte, p *Params) ([]byte, error) {
	h, err := New(p)
	if err != nil {
		return nil, err
	}
	h.Write(msg)
	return h.Sum(nil), nil
}

// Returns a new hash.Hash computing the blake2s checksum.
// The Params argument must not be nil and must contain valid
// parameters.
func New(p *Params) (hash.Hash, error) {
	if p == nil {
		return nil, errors.New("p argument must not be nil")
	}
	if err := verifyParams(p); err != nil {
		return nil, err
	}
	b := new(blake2s)
	b.initialize(p)
	return b, nil
}

func (h *blake2s) BlockSize() int { return BlockSize }

func (b *blake2s) Size() int { return b.hsize }

func (h *blake2s) Write(p []byte) (int, error) {
	n := len(p)

	if h.off > 0 {
		diff := BlockSize - h.off
		h.off += copy(h.buf[h.off:], p[:diff])
		if n > diff {
			update(&(h.hVal), &(h.ctr), msgBlock, h.buf[:])
			h.off = 0
			p = p[diff:]
		}
	}

	// process full blocks except for the last
	nn := len(p) & (^(BlockSize - 1))
	if len(p)-nn > 0 {
		update(&(h.hVal), &(h.ctr), msgBlock, p[:nn])
		p = p[nn:]
	}
	h.off += copy(h.buf[h.off:], p)
	return n, nil
}

func (h *blake2s) Reset() {
	h.hVal = h.initVal
	h.ctr[0], h.ctr[1] = 0, 0
	for i := range h.buf {
		h.buf[i] = 0
	}
	h.off = 0
	if h.keyed {
		h.Write(h.key[:])
	}
}

func (h *blake2s) Sum(b []byte) []byte {
	h0 := *h
	var out [Size]byte
	h0.finalize(&out)
	return append(b, out[:h0.hsize]...)
}

// Finalize the hash by adding padding bytes (if necessary)
// and extract the hash to a byte array.
func (h *blake2s) finalize(out *[Size]byte) {
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

	// process last block
	update(&(h.hVal), &(h.ctr), lastBlock, h.buf[:])

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
		j := i * 4
		pv := uint32(p[j+0]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
		h.hVal[i] = iv[i] ^ pv
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
