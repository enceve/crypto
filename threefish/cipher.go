// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The threefish package implements the tweakable
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
	"strconv"

	"github.com/EncEve/crypto"
)

const TweakSize = 16 // the size of the tweak in bytes.

const (
	blockSize256  = 32  // the blocksize of threefish-256 in bytes
	blockSize512  = 64  // the blocksize of threefish-512 in bytes
	blockSize1024 = 128 // the blocksize of threefish-1024 in bytes

	keySize256  = 32  // the keysize of threefish-256 in bytes
	keySize512  = 64  // the keysize of threefish-512 in bytes
	keySize1024 = 128 // the keysize of threefish-1024 in bytes
)

// New returns a cipher.Block implementing the Threefish cipher.
// The length of thekey must be 32 (256 bit), 64 (512 bit)
// or 128 (1024 bit). The length of the tweak must be 16 (128 bit).
// The returned cipher implement:
// - threefish-256 - if len(key) = 32 (256 bit)
// - threefish-512 - if len(key) = 64 (512 bit)
// - threefish1024 - if len(key) = 128 (1024 bit)
func New(key []byte, tweak []byte) (cipher.Block, error) {
	if t := len(tweak); t != TweakSize {
		return nil, TweakSizeError(t)
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

// New256 returns a cipher.Block implementing the Threefish-256 cipher.
// The length of the key must be 32 (256 bit) and the length of the
// tweak 16 (128 bit) byte.
func New256(key []byte, tweak []byte) (cipher.Block, error) {
	if t := len(tweak); t != TweakSize {
		return nil, TweakSizeError(t)
	}
	if k := len(key); k != keySize256 {
		return nil, crypto.KeySizeError(k)
	}

	c := new(treefish256)
	scheduleTweak(&(c.tweak), tweak)
	scheduleKey256(&(c.sk), key)
	return c, nil
}

// New512 returns a cipher.Block implementing the Threefish-512 cipher.
// The length of the key must be 64 (512 bit) and the length of the
// tweak 16 (128 bit) byte.
func New512(key []byte, tweak []byte) (cipher.Block, error) {
	if t := len(tweak); t != TweakSize {
		return nil, TweakSizeError(t)
	}
	if k := len(key); k != keySize512 {
		return nil, crypto.KeySizeError(k)
	}

	c := new(treefish512)
	scheduleTweak(&(c.tweak), tweak)
	scheduleKey512(&(c.sk), key)
	return c, nil
}

// New1024 returns a cipher.Block implementing the Threefish-1024 cipher.
// The length of the key must be 128 (1024 bit) and the length of the
// tweak 16 (128 bit) byte.
func New1024(key []byte, tweak []byte) (cipher.Block, error) {
	if t := len(tweak); t != TweakSize {
		return nil, TweakSizeError(t)
	}
	if k := len(key); k != keySize1024 {
		return nil, crypto.KeySizeError(k)
	}

	c := new(treefish1024)
	scheduleTweak(&(c.tweak), tweak)
	scheduleKey1024(&(c.sk), key)
	return c, nil
}

// A TweakSizeError indicates, that the actual size of a given
// tweak does not match the expected size.
type TweakSizeError int

func (t TweakSizeError) Error() string {
	return "invalid tweak size " + strconv.Itoa(int(t))
}

// The threefish-256 tweakable blockcipher
type treefish256 struct {
	sk    [5]uint64
	tweak [3]uint64
}

// The threefish-512 tweakable blockcipher
type treefish512 struct {
	sk    [9]uint64
	tweak [3]uint64
}

// The threefish-1024 tweakable blockcipher
type treefish1024 struct {
	sk    [17]uint64
	tweak [3]uint64
}

func (t *treefish256) BlockSize() int { return blockSize256 }

func (t *treefish512) BlockSize() int { return blockSize512 }

func (t *treefish1024) BlockSize() int { return blockSize1024 }

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
