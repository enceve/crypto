// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package blake2s implements the BLAKE2s hash function.
// BLAKE2s produces hash values from 8 to 256 bit (1 to 32 byte),
// and can be configured as a MAC. Furthermore BLAKE2s supports
// salted/randomized and personalized hashing.
// BLAKE2s can process messages up to 2^64 bytes, which is enough
// for almost all practical use cases.
package blake2s

import (
	"errors"
	"hash"
	"strconv"

	"github.com/enceve/crypto"
)

const (
	// The BLAKE2s block size in bytes.
	BlockSize = 64
	// The max. size of the BLAKE2s checksum
	Size = 32
)

// Config contains the BLAKE2s configuration:
// - Key for computing MACs
// - Salt for randomized hashing
// - Personal for personalized hashing
// All fields are optional and can be nil.
type Config struct {
	Key      []byte // The key for MAC (length must between 0 and 32)
	Salt     []byte // The salt (length must between 0 and 8)
	Personal []byte // The personalization for unique hashing (length must between 0 and 16)
}

// Configure takes the hash size and the BLAKE2s configuration and
// computes the 8 32-bit chain values. The conf is optional and can be nil,
// or must be a valid configuraton struct - otherwise a non-nil error is returned.
func Configure(hVal *[8]uint32, counter *[2]uint32, hashsize int, conf *Config) error {
	if hashsize <= 0 || hashsize > Size {
		errors.New("illegal hash size " + strconv.Itoa(hashsize))
	}

	var key, salt, personal []byte
	if conf != nil {
		key = conf.Key
		salt = conf.Salt
		personal = conf.Personal
	}
	if k := len(key); k > Size {
		return crypto.KeySizeError(k)
	}
	if s := len(salt); s > 8 {
		errors.New("illegal salt size " + strconv.Itoa(s))
	}
	if p := len(personal); p > 8 {
		errors.New("illegal personalization size " + strconv.Itoa(p))
	}

	var p [BlockSize]byte
	p[0] = byte(hashsize)
	p[1] = byte(len(key))
	p[2] = 1
	p[3] = 1
	if len(salt) > 0 {
		copy(p[16:], salt)
	}
	if len(personal) > 0 {
		copy(p[24:], personal)
	}

	for i := range iv {
		j := i * 4
		v := uint32(p[j+0]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
		hVal[i] = iv[i] ^ v
	}
	return nil
}

// Sum returns the BLAKE2s checksum with the given hash size of msg using the (optional)
// conf for configuration. This function returns a non-nil error if the configuration
// is invalid.
func Sum(msg []byte, hashsize int, conf *Config) ([]byte, error) {
	h, err := New(hashsize, conf)
	if err != nil {
		return nil, err
	}

	h.Write(msg)

	return h.Sum(nil), nil
}

// New returns a hash.Hash computing the BLAKE2s checksum with the given hash size
// using the (optional) conf for configuration. This function returns a non-nil error
// if the configuration is invalid.
func New(hashsize int, conf *Config) (hash.Hash, error) {
	h := new(hashFunc)
	if err := Configure(&(h.hVal), &(h.ctr), hashsize, conf); err != nil {
		return nil, err
	}
	h.hashsize = hashsize
	h.hValCpy = h.hVal

	if conf != nil && len(conf.Key) > 0 {
		copy(h.key[:], conf.Key)
		h.block = h.key
		h.off = BlockSize
		h.hasKey = true
	}
	return h, nil
}

// ExtractHash takes the 8 32-bit chain values, the 64-bit counter, the 64 byte block
// and a block-offset and extracts the checksum to out.
func ExtractHash(out *[Size]byte, hVal *[8]uint32, ctr *[2]uint32, block *[BlockSize]byte, off int) {
	diff := uint32(BlockSize - off)
	if ctr[0] < diff {
		ctr[1]--
	}
	ctr[0] -= diff

	for i := off; i < BlockSize; i++ {
		block[i] = 0
	}

	Core(hVal, ctr, FinalFlag, block[:])

	j := 0
	for _, s := range hVal {
		out[j+0] = byte(s >> 0)
		out[j+1] = byte(s >> 8)
		out[j+2] = byte(s >> 16)
		out[j+3] = byte(s >> 24)
		j += 4
	}
}

type hashFunc struct {
	hashsize      int             // the hash size in bytes
	hVal, hValCpy [8]uint32       // the chain values
	ctr           [2]uint32       // the counter (max 2^64 bytes)
	block         [BlockSize]byte // the buffer
	off           int             // the buffer offset

	hasKey bool            // flag indicating MAC usage
	key    [BlockSize]byte // the key for MAC
}

func (h *hashFunc) BlockSize() int { return BlockSize }

func (h *hashFunc) Size() int { return h.hashsize }

func (h *hashFunc) Write(p []byte) (int, error) {
	n := len(p)

	dif := BlockSize - h.off
	if h.off > 0 && n > dif {
		h.off += copy(h.block[h.off:], p[:dif])
		p = p[dif:]
		if h.off == BlockSize && len(p) > 0 {
			Core(&(h.hVal), &(h.ctr), MsgFlag, h.block[:])
			h.off = 0
		}
	}

	if length := len(p); length > BlockSize {
		nb := length & (^(BlockSize - 1)) // length -= (length % BlockSize)
		if length == nb {
			nb -= BlockSize
		}
		Core(&(h.hVal), &(h.ctr), MsgFlag, p[:nb])
		p = p[nb:]
	}
	if len(p) > 0 {
		h.off += copy(h.block[h.off:], p)
	}
	return n, nil
}

func (h *hashFunc) Reset() {
	h.hVal = h.hValCpy
	h.ctr[0], h.ctr[1] = 0, 0
	for i := range h.block {
		h.block[i] = 0
	}
	h.off = 0
	if h.hasKey {
		h.block = h.key
		h.off = BlockSize
	}
}

func (h *hashFunc) Sum(b []byte) []byte {
	hVal := h.hVal
	ctr := h.ctr
	buf := h.block
	off := h.off

	var out [Size]byte
	ExtractHash(&out, &hVal, &ctr, &buf, off)

	return append(b, out[:h.hashsize]...)
}
