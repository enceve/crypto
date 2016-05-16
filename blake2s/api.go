// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package blake2s implements the Blake2s hash function.
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

// Params contains the configuration for the blake2s hash function.
// All values are optional. If the HashSize is not between 1
// and 32 inclusively, it will be set to the default value.
type Params struct {
	HashSize int    // The hash size of blake2s in bytes (default and max. is 32)
	Key      []byte // The key for MAC (length must between 0 and 32)
	Salt     []byte // The salt (length must between 0 and 8)
}

// Sum256 returns the 256 bit blake2s checksum of the msg.
func Sum256(msg []byte) []byte {
	h := new(hashFunc)
	h.initialize(params256)
	h.Write(msg)
	return h.Sum(nil)
}

// Sum160 returns the 160 bit blake2s checksum of the msg.
func Sum160(msg []byte) []byte {
	h := new(hashFunc)
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

// New returns a new hash.Hash computing the blake2s checksum.
// The Params argument must not be nil and must contain valid
// parameters.
func New(p *Params) (hash.Hash, error) {
	if p == nil {
		return nil, errors.New("p argument must not be nil")
	}
	if err := verifyParams(p); err != nil {
		return nil, err
	}
	b := new(hashFunc)
	b.initialize(p)
	return b, nil
}

// the blake2s hash struct
type hashFunc struct {
	hVal [8]uint32       // the chain values
	ctr  [2]uint32       // the counter (max 2^64 bytes)
	buf  [BlockSize]byte // the buffer
	off  int             // the buffer offset

	initVal [8]uint32       // initial chain values
	keyed   bool            // flag whether a key is used (MAC)
	key     [BlockSize]byte // the key for MAC
	hsize   int             // the hash size in bytes
}

func (h *hashFunc) BlockSize() int { return BlockSize }

func (h *hashFunc) Size() int { return h.hsize }

func (h *hashFunc) Write(p []byte) (int, error) {
	n := len(p)

	if h.off > 0 {
		diff := BlockSize - h.off
		h.off += copy(h.buf[h.off:], p[:diff])
		if n > diff {
			blake2sCore(&(h.hVal), &(h.ctr), msgBlock, h.buf[:])
			h.off = 0
			p = p[diff:]
		}
	}

	// process full blocks except for the last
	nn := len(p) & (^(BlockSize - 1))
	if len(p)-nn > 0 {
		blake2sCore(&(h.hVal), &(h.ctr), msgBlock, p[:nn])
		p = p[nn:]
	}
	h.off += copy(h.buf[h.off:], p)
	return n, nil
}

func (h *hashFunc) Reset() {
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

func (h *hashFunc) Sum(b []byte) []byte {
	h0 := *h
	var out [Size]byte
	h0.finalize(&out)
	return append(b, out[:h0.hsize]...)
}
