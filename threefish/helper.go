// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package threefish

const (
	blockSize256  = 32  // the blocksize of threefish-256 in bytes
	blockSize512  = 64  // the blocksize of threefish-512 in bytes
	blockSize1024 = 128 // the blocksize of threefish-1024 in bytes

	keySize256  = 32  // the keysize of threefish-256 in bytes
	keySize512  = 64  // the keysize of threefish-512 in bytes
	keySize1024 = 128 // the keysize of threefish-1024 in bytes
)

// expands the binary 128 bit tweak
// to two 64 bit tweak words
func scheduleTweak(dst *[3]uint64, tweak []byte) {
	dst[2] = 0
	for i := range dst[:2] {
		j := i * 8
		dst[i] = uint64(tweak[j]) | uint64(tweak[j+1])<<8 | uint64(tweak[j+2])<<16 | uint64(tweak[j+3])<<24 |
			uint64(tweak[j+4])<<32 | uint64(tweak[j+5])<<40 | uint64(tweak[j+6])<<48 | uint64(tweak[j+7])<<56
		dst[2] ^= dst[i]
	}
}

// expands the binary 256 bit key
// to 4 64 bit tweak words
func scheduleKey256(dst *[5]uint64, key []byte) {
	dst[4] = 0
	for i := range dst[:4] {
		j := i * 8
		dst[i] = uint64(key[j]) | uint64(key[j+1])<<8 | uint64(key[j+2])<<16 | uint64(key[j+3])<<24 |
			uint64(key[j+4])<<32 | uint64(key[j+5])<<40 | uint64(key[j+6])<<48 | uint64(key[j+7])<<56
		dst[4] ^= dst[i]
	}
	dst[4] ^= C240
}

// expands the binary 512 bit key
// to 8 64 bit tweak words
func scheduleKey512(dst *[9]uint64, key []byte) {
	dst[8] = 0
	for i := range dst[:8] {
		j := i * 8
		dst[i] = uint64(key[j]) | uint64(key[j+1])<<8 | uint64(key[j+2])<<16 | uint64(key[j+3])<<24 |
			uint64(key[j+4])<<32 | uint64(key[j+5])<<40 | uint64(key[j+6])<<48 | uint64(key[j+7])<<56
		dst[8] ^= dst[i]
	}
	dst[8] ^= C240
}

// expands the binary 1024 bit key
// to 16 64 bit tweak words
func scheduleKey1024(dst *[17]uint64, key []byte) {
	dst[16] = 0
	for i := range dst[:16] {
		j := i * 8
		dst[i] = uint64(key[j]) | uint64(key[j+1])<<8 | uint64(key[j+2])<<16 | uint64(key[j+3])<<24 |
			uint64(key[j+4])<<32 | uint64(key[j+5])<<40 | uint64(key[j+6])<<48 | uint64(key[j+7])<<56
		dst[16] ^= dst[i]
	}
	dst[16] ^= C240
}
