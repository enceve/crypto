// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The camellia package implements the camellia block cipher.
// The cipher has block size of 128 bit (16 byte) and
// accepts 128, 192 or 256 bit keys (16, 24, 32 byte).
// Camellia was jointly developed by Mitsubishi Electric
// and NTT of Japan.
// Camellia was added to many crypto protocols (e.g. TLS).
package camellia

import (
	"crypto/cipher"

	"github.com/EncEve/crypto"
)

const BlockSize = 16 // The block size of the camellia block cipher in bytes.

// NewCipher returns a new cipher.Block implementing the camellia cipher.
// The key argument must be 128, 192 or 256 bit (16, 24, 32 byte).
func NewCipher(key []byte) (cipher.Block, error) {
	k := len(key)
	if k == 16 {
		c := new(blockCipher128)
		c.keySchedule(key)
		return c, nil
	}
	if k == 24 || k == 32 {
		c := new(blockCipher256)
		c.keySchedule(key)
		return c, nil
	}
	return nil, crypto.KeySizeError(k)
}

// The camellia cipher for 128 bit keys.
type blockCipher128 struct {
	sk [52]uint32 // The 52 32-bit subkeys
}

func (c *blockCipher128) BlockSize() int { return BlockSize }

func (c *blockCipher128) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("dst buffer to small")
	}

	r0 := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r1 := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	r2 := uint32(src[8])<<24 | uint32(src[9])<<16 | uint32(src[10])<<8 | uint32(src[11])
	r3 := uint32(src[12])<<24 | uint32(src[13])<<16 | uint32(src[14])<<8 | uint32(src[15])

	k := &(c.sk)

	r0 ^= k[0]
	r1 ^= k[1]
	r2 ^= k[2]
	r3 ^= k[3]

	f(&r0, &r1, &r2, &r3, k[4], k[5])
	f(&r2, &r3, &r0, &r1, k[6], k[7])
	f(&r0, &r1, &r2, &r3, k[8], k[9])
	f(&r2, &r3, &r0, &r1, k[10], k[11])
	f(&r0, &r1, &r2, &r3, k[12], k[13])
	f(&r2, &r3, &r0, &r1, k[14], k[15])

	t := r0 & k[16]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[19]
	r0 ^= r1 | k[17]
	t = r2 & k[18]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[20], k[21])
	f(&r2, &r3, &r0, &r1, k[22], k[23])
	f(&r0, &r1, &r2, &r3, k[24], k[25])
	f(&r2, &r3, &r0, &r1, k[26], k[27])
	f(&r0, &r1, &r2, &r3, k[28], k[29])
	f(&r2, &r3, &r0, &r1, k[30], k[31])

	t = r0 & k[32]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[35]
	r0 ^= r1 | k[33]
	t = r2 & k[34]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[36], k[37])
	f(&r2, &r3, &r0, &r1, k[38], k[39])
	f(&r0, &r1, &r2, &r3, k[40], k[41])
	f(&r2, &r3, &r0, &r1, k[42], k[43])
	f(&r0, &r1, &r2, &r3, k[44], k[45])
	f(&r2, &r3, &r0, &r1, k[46], k[47])

	r2 ^= k[48]
	r3 ^= k[49]
	r0 ^= k[50]
	r1 ^= k[51]

	dst[0] = byte(r2 >> 24)
	dst[1] = byte(r2 >> 16)
	dst[2] = byte(r2 >> 8)
	dst[3] = byte(r2)
	dst[4] = byte(r3 >> 24)
	dst[5] = byte(r3 >> 16)
	dst[6] = byte(r3 >> 8)
	dst[7] = byte(r3)
	dst[8] = byte(r0 >> 24)
	dst[9] = byte(r0 >> 16)
	dst[10] = byte(r0 >> 8)
	dst[11] = byte(r0)
	dst[12] = byte(r1 >> 24)
	dst[13] = byte(r1 >> 16)
	dst[14] = byte(r1 >> 8)
	dst[15] = byte(r1)
}

func (c *blockCipher128) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("dst buffer to small")
	}

	r0 := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r1 := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	r2 := uint32(src[8])<<24 | uint32(src[9])<<16 | uint32(src[10])<<8 | uint32(src[11])
	r3 := uint32(src[12])<<24 | uint32(src[13])<<16 | uint32(src[14])<<8 | uint32(src[15])

	k := &(c.sk)

	r3 ^= k[51]
	r2 ^= k[50]
	r1 ^= k[49]
	r0 ^= k[48]

	f(&r0, &r1, &r2, &r3, k[46], k[47])
	f(&r2, &r3, &r0, &r1, k[44], k[45])
	f(&r0, &r1, &r2, &r3, k[42], k[43])
	f(&r2, &r3, &r0, &r1, k[40], k[41])
	f(&r0, &r1, &r2, &r3, k[38], k[39])
	f(&r2, &r3, &r0, &r1, k[36], k[37])

	t := r0 & k[34]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[33]
	r0 ^= r1 | k[35]
	t = r2 & k[32]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[30], k[31])
	f(&r2, &r3, &r0, &r1, k[28], k[29])
	f(&r0, &r1, &r2, &r3, k[26], k[27])
	f(&r2, &r3, &r0, &r1, k[24], k[25])
	f(&r0, &r1, &r2, &r3, k[22], k[23])
	f(&r2, &r3, &r0, &r1, k[20], k[21])

	t = r0 & k[18]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[17]
	r0 ^= r1 | k[19]
	t = r2 & k[16]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[14], k[15])
	f(&r2, &r3, &r0, &r1, k[12], k[13])
	f(&r0, &r1, &r2, &r3, k[10], k[11])
	f(&r2, &r3, &r0, &r1, k[8], k[9])
	f(&r0, &r1, &r2, &r3, k[6], k[7])
	f(&r2, &r3, &r0, &r1, k[4], k[5])

	r1 ^= k[3]
	r0 ^= k[2]
	r3 ^= k[1]
	r2 ^= k[0]

	dst[0] = byte(r2 >> 24)
	dst[1] = byte(r2 >> 16)
	dst[2] = byte(r2 >> 8)
	dst[3] = byte(r2)
	dst[4] = byte(r3 >> 24)
	dst[5] = byte(r3 >> 16)
	dst[6] = byte(r3 >> 8)
	dst[7] = byte(r3)
	dst[8] = byte(r0 >> 24)
	dst[9] = byte(r0 >> 16)
	dst[10] = byte(r0 >> 8)
	dst[11] = byte(r0)
	dst[12] = byte(r1 >> 24)
	dst[13] = byte(r1 >> 16)
	dst[14] = byte(r1 >> 8)
	dst[15] = byte(r1)
}

// The camellia cipher for 192 or 256 bit keys.
type blockCipher256 struct {
	sk [68]uint32 // The 68 32-bit subkeys
}

func (c *blockCipher256) BlockSize() int { return BlockSize }

func (c *blockCipher256) Encrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("dst buffer to small")
	}

	r0 := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r1 := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	r2 := uint32(src[8])<<24 | uint32(src[9])<<16 | uint32(src[10])<<8 | uint32(src[11])
	r3 := uint32(src[12])<<24 | uint32(src[13])<<16 | uint32(src[14])<<8 | uint32(src[15])

	k := &(c.sk)

	r0 ^= k[0]
	r1 ^= k[1]
	r2 ^= k[2]
	r3 ^= k[3]

	f(&r0, &r1, &r2, &r3, k[4], k[5])
	f(&r2, &r3, &r0, &r1, k[6], k[7])
	f(&r0, &r1, &r2, &r3, k[8], k[9])
	f(&r2, &r3, &r0, &r1, k[10], k[11])
	f(&r0, &r1, &r2, &r3, k[12], k[13])
	f(&r2, &r3, &r0, &r1, k[14], k[15])

	t := r0 & k[16]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[19]
	r0 ^= r1 | k[17]
	t = r2 & k[18]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[20], k[21])
	f(&r2, &r3, &r0, &r1, k[22], k[23])
	f(&r0, &r1, &r2, &r3, k[24], k[25])
	f(&r2, &r3, &r0, &r1, k[26], k[27])
	f(&r0, &r1, &r2, &r3, k[28], k[29])
	f(&r2, &r3, &r0, &r1, k[30], k[31])

	t = r0 & k[32]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[35]
	r0 ^= r1 | k[33]
	t = r2 & k[34]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[36], k[37])
	f(&r2, &r3, &r0, &r1, k[38], k[39])
	f(&r0, &r1, &r2, &r3, k[40], k[41])
	f(&r2, &r3, &r0, &r1, k[42], k[43])
	f(&r0, &r1, &r2, &r3, k[44], k[45])
	f(&r2, &r3, &r0, &r1, k[46], k[47])

	t = r0 & k[48]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[51]
	r0 ^= r1 | k[49]
	t = r2 & k[50]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[52], k[53])
	f(&r2, &r3, &r0, &r1, k[54], k[55])
	f(&r0, &r1, &r2, &r3, k[56], k[57])
	f(&r2, &r3, &r0, &r1, k[58], k[59])
	f(&r0, &r1, &r2, &r3, k[60], k[61])
	f(&r2, &r3, &r0, &r1, k[62], k[63])

	r2 ^= c.sk[64]
	r3 ^= c.sk[65]
	r0 ^= c.sk[66]
	r1 ^= c.sk[67]

	dst[0] = byte(r2 >> 24)
	dst[1] = byte(r2 >> 16)
	dst[2] = byte(r2 >> 8)
	dst[3] = byte(r2)
	dst[4] = byte(r3 >> 24)
	dst[5] = byte(r3 >> 16)
	dst[6] = byte(r3 >> 8)
	dst[7] = byte(r3)
	dst[8] = byte(r0 >> 24)
	dst[9] = byte(r0 >> 16)
	dst[10] = byte(r0 >> 8)
	dst[11] = byte(r0)
	dst[12] = byte(r1 >> 24)
	dst[13] = byte(r1 >> 16)
	dst[14] = byte(r1 >> 8)
	dst[15] = byte(r1)
}

func (c *blockCipher256) Decrypt(dst, src []byte) {
	if len(src) < BlockSize {
		panic("src buffer to small")
	}
	if len(dst) < BlockSize {
		panic("dst buffer to small")
	}

	r0 := uint32(src[0])<<24 | uint32(src[1])<<16 | uint32(src[2])<<8 | uint32(src[3])
	r1 := uint32(src[4])<<24 | uint32(src[5])<<16 | uint32(src[6])<<8 | uint32(src[7])
	r2 := uint32(src[8])<<24 | uint32(src[9])<<16 | uint32(src[10])<<8 | uint32(src[11])
	r3 := uint32(src[12])<<24 | uint32(src[13])<<16 | uint32(src[14])<<8 | uint32(src[15])

	k := &(c.sk)

	r3 ^= k[67]
	r2 ^= k[66]
	r1 ^= k[65]
	r0 ^= k[64]

	f(&r0, &r1, &r2, &r3, k[62], k[63])
	f(&r2, &r3, &r0, &r1, k[60], k[61])
	f(&r0, &r1, &r2, &r3, k[58], k[59])
	f(&r2, &r3, &r0, &r1, k[56], k[57])
	f(&r0, &r1, &r2, &r3, k[54], k[55])
	f(&r2, &r3, &r0, &r1, k[52], k[53])

	t := r0 & k[50]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[49]
	r0 ^= r1 | k[51]
	t = r2 & k[48]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[46], k[47])
	f(&r2, &r3, &r0, &r1, k[44], k[45])
	f(&r0, &r1, &r2, &r3, k[42], k[43])
	f(&r2, &r3, &r0, &r1, k[40], k[41])
	f(&r0, &r1, &r2, &r3, k[38], k[39])
	f(&r2, &r3, &r0, &r1, k[36], k[37])

	t = r0 & k[34]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[33]
	r0 ^= r1 | k[35]
	t = r2 & k[32]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[30], k[31])
	f(&r2, &r3, &r0, &r1, k[28], k[29])
	f(&r0, &r1, &r2, &r3, k[26], k[27])
	f(&r2, &r3, &r0, &r1, k[24], k[25])
	f(&r0, &r1, &r2, &r3, k[22], k[23])
	f(&r2, &r3, &r0, &r1, k[20], k[21])

	t = r0 & k[18]
	r1 ^= (t << 1) | (t >> (32 - 1))
	r2 ^= r3 | k[17]
	r0 ^= r1 | k[19]
	t = r2 & k[16]
	r3 ^= (t << 1) | (t >> (32 - 1))

	f(&r0, &r1, &r2, &r3, k[14], k[15])
	f(&r2, &r3, &r0, &r1, k[12], k[13])
	f(&r0, &r1, &r2, &r3, k[10], k[11])
	f(&r2, &r3, &r0, &r1, k[8], k[9])
	f(&r0, &r1, &r2, &r3, k[6], k[7])
	f(&r2, &r3, &r0, &r1, k[4], k[5])

	r1 ^= k[3]
	r0 ^= k[2]
	r3 ^= k[1]
	r2 ^= k[0]

	dst[0] = byte(r2 >> 24)
	dst[1] = byte(r2 >> 16)
	dst[2] = byte(r2 >> 8)
	dst[3] = byte(r2)
	dst[4] = byte(r3 >> 24)
	dst[5] = byte(r3 >> 16)
	dst[6] = byte(r3 >> 8)
	dst[7] = byte(r3)
	dst[8] = byte(r0 >> 24)
	dst[9] = byte(r0 >> 16)
	dst[10] = byte(r0 >> 8)
	dst[11] = byte(r0)
	dst[12] = byte(r1 >> 24)
	dst[13] = byte(r1 >> 16)
	dst[14] = byte(r1 >> 8)
	dst[15] = byte(r1)
}
