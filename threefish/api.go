// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package threefish implements the tweakable
// block cipher Threefish designed by Niels Ferguson,
// Stefan Lucks, Bruce Schneier, Doug Whiting,
// Mihir Bellare, Tadayoshi Kohno, Jon Callas and
// Jesse Walker. Threefish is part of the hash function
// skein, submitted to the SHA3 competition.
// This implementation supports the three Threefish
// variants:
//     - Threefish-256
//     - Threefish-512
//     - Threefish-1024
package threefish

import (
	"crypto/cipher"

	"github.com/enceve/crypto"
)

const (
	// The size of the tweak in bytes.
	TweakSize = 16
	// C240 is the key schedule constant
	C240 = 0x1bd11bdaa9fc1a22
)

// NewCipher returns a cipher.Block implementing the Threefish cipher.
// The length of the key must be 32 (256 bit), 64 (512 bit)
// or 128 (1024 bit). The length of the tweak must be 16 (128 bit).
// The returned cipher implements:
// - threefish-256  - if len(key) = 32  (256 bit)
// - threefish-512  - if len(key) = 64  (512 bit)
// - threefish-1024 - if len(key) = 128 (1024 bit)
func NewCipher(key []byte, tweak []byte) (cipher.Block, error) {
	if t := len(tweak); t != TweakSize {
		return nil, crypto.TweakSizeError(t)
	}
	switch k := len(key); k {
	default:
		return nil, crypto.KeySizeError(k)
	case keySize256:
		c := new(treefish256)
		scheduleTweak(&(c.tweak), tweak)
		scheduleKey256(&(c.sk), key)
		return c, nil
	case keySize512:
		c := new(treefish512)
		scheduleTweak(&(c.tweak), tweak)
		scheduleKey512(&(c.sk), key)
		return c, nil
	case keySize1024:
		c := new(treefish1024)
		scheduleTweak(&(c.tweak), tweak)
		scheduleKey1024(&(c.sk), key)
		return c, nil
	}
}

// The threefish-256 tweakable blockcipher
type treefish256 struct {
	sk    [5]uint64
	tweak [3]uint64
}

func (t *treefish256) BlockSize() int { return blockSize256 }

func (t *treefish256) Encrypt(dst, src []byte) {
	var msg [4]uint64
	for i := range msg {
		j := i * 8
		msg[i] = uint64(src[j]) | uint64(src[j+1])<<8 | uint64(src[j+2])<<16 | uint64(src[j+3])<<24 |
			uint64(src[j+4])<<32 | uint64(src[j+5])<<40 | uint64(src[j+6])<<48 | uint64(src[j+7])<<56
	}

	Encrypt256(&(t.sk), &(t.tweak), &msg)

	for i, v := range msg {
		j := i * 8
		dst[j] = byte(v)
		dst[j+1] = byte(v >> 8)
		dst[j+2] = byte(v >> 16)
		dst[j+3] = byte(v >> 24)
		dst[j+4] = byte(v >> 32)
		dst[j+5] = byte(v >> 40)
		dst[j+6] = byte(v >> 48)
		dst[j+7] = byte(v >> 56)
	}
}

func (t *treefish256) Decrypt(dst, src []byte) {
	var msg [4]uint64
	for i := range msg {
		j := i * 8
		msg[i] = uint64(src[j]) | uint64(src[j+1])<<8 | uint64(src[j+2])<<16 | uint64(src[j+3])<<24 |
			uint64(src[j+4])<<32 | uint64(src[j+5])<<40 | uint64(src[j+6])<<48 | uint64(src[j+7])<<56
	}

	Decrypt256(&(t.sk), &(t.tweak), &msg)

	for i, v := range msg {
		j := i * 8
		dst[j] = byte(v)
		dst[j+1] = byte(v >> 8)
		dst[j+2] = byte(v >> 16)
		dst[j+3] = byte(v >> 24)
		dst[j+4] = byte(v >> 32)
		dst[j+5] = byte(v >> 40)
		dst[j+6] = byte(v >> 48)
		dst[j+7] = byte(v >> 56)
	}
}

// The threefish-512 tweakable blockcipher
type treefish512 struct {
	sk    [9]uint64
	tweak [3]uint64
}

func (t *treefish512) BlockSize() int { return blockSize512 }

func (t *treefish512) Encrypt(dst, src []byte) {
	var msg [8]uint64
	for i := range msg {
		j := i * 8
		msg[i] = uint64(src[j]) | uint64(src[j+1])<<8 | uint64(src[j+2])<<16 | uint64(src[j+3])<<24 |
			uint64(src[j+4])<<32 | uint64(src[j+5])<<40 | uint64(src[j+6])<<48 | uint64(src[j+7])<<56
	}

	Encrypt512(&(t.sk), &(t.tweak), &msg)

	for i, v := range msg {
		j := i * 8
		dst[j] = byte(v)
		dst[j+1] = byte(v >> 8)
		dst[j+2] = byte(v >> 16)
		dst[j+3] = byte(v >> 24)
		dst[j+4] = byte(v >> 32)
		dst[j+5] = byte(v >> 40)
		dst[j+6] = byte(v >> 48)
		dst[j+7] = byte(v >> 56)
	}
}

func (t *treefish512) Decrypt(dst, src []byte) {
	var msg [8]uint64
	for i := range msg {
		j := i * 8
		msg[i] = uint64(src[j]) | uint64(src[j+1])<<8 | uint64(src[j+2])<<16 | uint64(src[j+3])<<24 |
			uint64(src[j+4])<<32 | uint64(src[j+5])<<40 | uint64(src[j+6])<<48 | uint64(src[j+7])<<56
	}

	Decrypt512(&(t.sk), &(t.tweak), &msg)

	for i, v := range msg {
		j := i * 8
		dst[j] = byte(v)
		dst[j+1] = byte(v >> 8)
		dst[j+2] = byte(v >> 16)
		dst[j+3] = byte(v >> 24)
		dst[j+4] = byte(v >> 32)
		dst[j+5] = byte(v >> 40)
		dst[j+6] = byte(v >> 48)
		dst[j+7] = byte(v >> 56)
	}
}

// The threefish-1024 tweakable blockcipher
type treefish1024 struct {
	sk    [17]uint64
	tweak [3]uint64
}

func (t *treefish1024) BlockSize() int { return blockSize1024 }

func (t *treefish1024) Encrypt(dst, src []byte) {
	var msg [16]uint64
	for i := range msg {
		j := i * 8
		msg[i] = uint64(src[j]) | uint64(src[j+1])<<8 | uint64(src[j+2])<<16 | uint64(src[j+3])<<24 |
			uint64(src[j+4])<<32 | uint64(src[j+5])<<40 | uint64(src[j+6])<<48 | uint64(src[j+7])<<56
	}

	Encrypt1024(&(t.sk), &(t.tweak), &msg)

	for i, v := range msg {
		j := i * 8
		dst[j] = byte(v)
		dst[j+1] = byte(v >> 8)
		dst[j+2] = byte(v >> 16)
		dst[j+3] = byte(v >> 24)
		dst[j+4] = byte(v >> 32)
		dst[j+5] = byte(v >> 40)
		dst[j+6] = byte(v >> 48)
		dst[j+7] = byte(v >> 56)
	}
}

func (t *treefish1024) Decrypt(dst, src []byte) {
	var msg [16]uint64
	for i := range msg {
		j := i * 8
		msg[i] = uint64(src[j]) | uint64(src[j+1])<<8 | uint64(src[j+2])<<16 | uint64(src[j+3])<<24 |
			uint64(src[j+4])<<32 | uint64(src[j+5])<<40 | uint64(src[j+6])<<48 | uint64(src[j+7])<<56
	}

	Decrypt1024(&(t.sk), &(t.tweak), &msg)

	for i, v := range msg {
		j := i * 8
		dst[j] = byte(v)
		dst[j+1] = byte(v >> 8)
		dst[j+2] = byte(v >> 16)
		dst[j+3] = byte(v >> 24)
		dst[j+4] = byte(v >> 32)
		dst[j+5] = byte(v >> 40)
		dst[j+6] = byte(v >> 48)
		dst[j+7] = byte(v >> 56)
	}
}
