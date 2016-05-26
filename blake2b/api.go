// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package blake2b implements the Blake2b hash function
// based on the RFC 7693 (https://tools.ietf.org/html/rfc7693).
// Blake2b is the 64 bit version of the blake2 hash function
// and supports hash values from 8 to 512 bit (1 to 64 byte).
// The package API directly supports 256 and 512 bit
// hash values, but custom sizes can be used as well.
// Furthermore blake2b supports randomized hashing and can be
// used as a MAC.
package blake2b

import (
	"errors"
	"hash"
)

// Params contains the configuration for the blake2b hash function.
// All values are optional. If the HashSize is not between 1
// and 64 inclusively, it will be set to the default value.
type Params struct {
	HashSize int    // The hash size of blake2b in bytes (default and max. is 64)
	Key      []byte // The key for MAC (length must between 0 and 64)
	Salt     []byte // The salt (length must between 0 and 16)
}

// Sum512 returns the 512 bit blake2b checksum of the msg.
func Sum512(out *[Size]byte, msg []byte) {
	var (
		hVal [8]uint64
		ctr  [2]uint64
		buf  [BlockSize]byte
		off  int
	)
	hVal = hVal512

	msgLen := len(msg)
	n := msgLen & (^(BlockSize - 1))
	if msgLen > n {
		blake2bCore(&hVal, &ctr, msgBlock, msg[:n])
		msg = msg[n:]
	}
	off += copy(buf[:], msg)
	finalize(out, &hVal, &ctr, &buf, off)
}

// Sum computes the blake2b checksum of the msg.
// The Params argument contains the blake2b configuration.
func Sum(msg []byte, p *Params) ([]byte, error) {
	h, err := New(p)
	if err != nil {
		return nil, err
	}
	h.Write(msg)
	return h.Sum(nil), nil
}

// New returns a new hash.Hash computing the blake2b checksum.
// The Params argument contains the blake2b configuration.
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

// the blake2b hash function
type hashFunc struct {
	hVal [8]uint64       // the chain values
	ctr  [2]uint64       // the counter (max 2^128 bytes)
	buf  [BlockSize]byte // the buffer
	off  int             // the buffer offset

	initVal [8]uint64       // initial chain values
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
			blake2bCore(&(h.hVal), &(h.ctr), msgBlock, h.buf[:])
			h.off = 0
			p = p[diff:]
		}
	}

	// process full blocks except for the last
	nn := len(p) & (^(BlockSize - 1))
	if len(p)-nn > 0 {
		blake2bCore(&(h.hVal), &(h.ctr), msgBlock, p[:nn])
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
	finalize(&out, &(h0.hVal), &(h0.ctr), &(h0.buf), h.off)
	return append(b, out[:h0.hsize]...)
}
