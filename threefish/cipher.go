// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The threefish package implements the tweakable
// blockcipher threefish designed by Niels Ferguson,
// Stefan Lucks, Bruce Schneier, Doug Whiting,
// Mihir Bellare, Tadayoshi Kohno, Jon Callas and
// Jesse Walker. Threefish is part of the hash function
// skein, submitted to the SHA3 competition.
// This implementation supports the three threefish
// variants:
//     - Threefish-256
//     - Threefish-512
//     - Threefish-1024
package threefish

import (
	"crypto/cipher"
	"github.com/EncEve/crypto"
	"strconv"
)

const (
	BlockSize256  = 32  // the blocksize of threefish-256 in bytes
	BlockSize512  = 64  // the blocksize of threefish-512 in bytes
	BlockSize1024 = 128 // the blocksize of threefish-1024 in bytes

	KeySize256  = 32  // the keysize of threefish-256 in bytes
	KeySize512  = 64  // the keysize of threefish-512 in bytes
	KeySize1024 = 128 // the keysize of threefish-1024 in bytes

	TweakSize = 16 // the size of the tweak in bytes
)

// Creates a new threefish cipher. The blocksize of the returned
// cipher depends on the given key:
// - for len(key) = 32 (256 bit) threefish-256
// - for len(key) = 64 (512 bit) threefish-512
// - for len(key) = 128 (1024 bit) threefish-1024
// if the length of the key is not 32, 64 , or 128 or the
// length of the tweak is not 16 this function returns an error.
func New(key []byte, tweak []byte) (cipher.Block, error) {
	if t := len(tweak); t != TweakSize {
		return nil, TweakSizeError(t)
	}
	switch k := len(key); k {
	case KeySize256:
		{
			c := new(treefish256)
			scheduleTweak(&(c.tweak), tweak)
			scheduleKey256(&(c.sk), key)
			return c, nil
		}
	case KeySize512:
		{
			c := new(treefish512)
			scheduleTweak(&(c.tweak), tweak)
			scheduleKey512(&(c.sk), key)
			return c, nil
		}
	case KeySize1024:
		{
			c := new(treefish1024)
			scheduleTweak(&(c.tweak), tweak)
			scheduleKey1024(&(c.sk), key)
			return c, nil
		}
	default:
		return nil, crypto.KeySizeError(k)
	}
}

// Creates a new threefish-256 cipher. The key must be 256
// and the tweak 128 bit. If the length of key or tweak does
// not match, an error is returned.
func New256(key []byte, tweak []byte) (cipher.Block, error) {
	if t := len(tweak); t != TweakSize {
		return nil, TweakSizeError(t)
	}
	if k := len(key); k != KeySize256 {
		return nil, crypto.KeySizeError(k)
	}

	c := new(treefish256)
	scheduleTweak(&(c.tweak), tweak)
	scheduleKey256(&(c.sk), key)
	return c, nil
}

// Creates a new threefish-512 cipher. The key must be 512
// and the tweak 128 bit. If the length of key or tweak does
// not match, an error is returned.
func New512(key []byte, tweak []byte) (cipher.Block, error) {
	if t := len(tweak); t != TweakSize {
		return nil, TweakSizeError(t)
	}
	if k := len(key); k != KeySize512 {
		return nil, crypto.KeySizeError(k)
	}

	c := new(treefish512)
	scheduleTweak(&(c.tweak), tweak)
	scheduleKey512(&(c.sk), key)
	return c, nil
}

// Creates a new threefish-1024 cipher. The key must be 1024
// and the tweak 128 bit. If the length of key or tweak does
// not match, an error is returned.
func New1024(key []byte, tweak []byte) (cipher.Block, error) {
	if t := len(tweak); t != TweakSize {
		return nil, TweakSizeError(t)
	}
	if k := len(key); k != KeySize1024 {
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

// Returns the threefish-256 block size in bytes.
func (t *treefish256) BlockSize() int { return BlockSize256 }

// Returns the threefish-512 block size in bytes.
func (t *treefish512) BlockSize() int { return BlockSize512 }

// Returns the threefish-1024 block size in bytes.
func (t *treefish1024) BlockSize() int { return BlockSize1024 }

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory.
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

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory.
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

// Encrypt encrypts the first block in src into dst.
// Dst and src may point at the same memory.
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

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory.
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

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory.
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

// Decrypt decrypts the first block in src into dst.
// Dst and src may point at the same memory.
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

// Sets the tweak for the threefish-256 cipher.
// The tweak must be 128 bit long, otherwise an
// error is returned and the tweak of the cipher
// will NOT be changed.
func (t *treefish256) Tweak(tweak []byte) error {
	if t := len(tweak); t != TweakSize {
		return TweakSizeError(t)
	}
	scheduleTweak(&(t.tweak), tweak)
	return nil
}

// Sets the tweak for the threefish-512 cipher.
// The tweak must be 128 bit long, otherwise an
// error is returned and the tweak of the cipher
// will NOT be changed.
func (t *treefish512) Tweak(tweak []byte) error {
	if t := len(tweak); t != TweakSize {
		return TweakSizeError(t)
	}
	scheduleTweak(&(t.tweak), tweak)
	return nil
}

// Sets the tweak for the threefish-1024 cipher.
// The tweak must be 128 bit long, otherwise an
// error is returned and the tweak of the cipher
// will NOT be changed.
func (t *treefish1024) Tweak(tweak []byte) error {
	if t := len(tweak); t != TweakSize {
		return TweakSizeError(t)
	}
	scheduleTweak(&(t.tweak), tweak)
	return nil
}
