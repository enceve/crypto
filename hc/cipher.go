// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The hc package implements the both stream ciphers
// HC128 and HC256 from the eSTREAM portfolio (software).
// Both ciphers were designed by Hongjun Wu.
package hc

import (
	"crypto/cipher"
	"strconv"
)

const (
	mod512  = 0x1FF
	mod1024 = 0x3FF
	mod2048 = 0x7FF
)

type KeySizeError int
type IvSizeError int

func (e KeySizeError) Error() string { return "hc: invalid key size " + strconv.Itoa(int(e)) }
func (e IvSizeError) Error() string  { return "hc: invalid iv size " + strconv.Itoa(int(e)) }

// A hc128 holds the both states P and Q, the counter,
// 4 byte of the keystream and the offset
type hc128 struct {
	p, q        []uint32
	ctr, stream uint32
	off         uint
}

// A hc256 holds the both states P and Q, the counter,
// 4 byte of the keystream and the offset
type hc256 struct {
	p, q        []uint32
	ctr, stream uint32
	off         uint
}

// New128 creates and returns a new cipher.Stream.
// The key argument must be 128 bit (16 byte),
// The iv argument must be 128 bit (16 byte),
// The returned cipher.Stream implements the HC128 cipher.
func New128(key, iv []byte) (cipher.Stream, error) {
	if k := len(key); k != 16 {
		return nil, KeySizeError(k)
	}
	if k := len(iv); k != 16 {
		return nil, IvSizeError(k)
	}
	c := &hc128{
		p:      make([]uint32, 512),
		q:      make([]uint32, 512),
		off:    4,
		ctr:    0,
		stream: 0,
	}
	c.initialize(key, iv)

	return c, nil
}

// New256 creates and returns a new cipher.Stream.
// The key argument must be 256 bit (32 byte),
// The iv argument must be 256 bit (32 byte),
// The returned cipher.Stream implements the HC256 cipher.
func New256(key, iv []byte) (cipher.Stream, error) {
	if k := len(key); k != 32 {
		return nil, KeySizeError(k)
	}
	if k := len(iv); k != 32 {
		return nil, IvSizeError(k)
	}
	c := &hc256{
		p:      make([]uint32, 1024),
		q:      make([]uint32, 1024),
		off:    4,
		ctr:    0,
		stream: 0,
	}
	c.initialize(key, iv)

	return c, nil
}
