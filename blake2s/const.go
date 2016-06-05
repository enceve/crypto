// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package blake2s

const (
	// The block size of BLAKE2s in bytes.
	BlockSize = 64
	// The max. hash size of BLAKE2s in bytes.
	Size = 32
)

const (
	keySize          = 32         // The max. key size in bytes.
	saltSize         = 8          // The max. salt size in bytes.
	msgBlock  uint32 = 0          // The block flag for message blocks
	lastBlock uint32 = 0xffffffff // The last block flag
)

// the BLAKE2s iv constants
var iv = [8]uint32{
	0x6a09e667,
	0xbb67ae85,
	0x3c6ef372,
	0xa54ff53a,
	0x510e527f,
	0x9b05688c,
	0x1f83d9ab,
	0x5be0cd19,
}

// the precomputed values for BLAKE2s
// there are 12 16-byte arrays - one for each round
// the entries are calculated from the sigma constants.
var precomputed [10][16]byte = [10][16]byte{
	{0, 2, 4, 6, 5, 7, 3, 1, 8, 10, 12, 14, 13, 15, 11, 9},
	{14, 4, 9, 13, 15, 6, 8, 10, 1, 0, 11, 5, 7, 3, 2, 12},
	{11, 12, 5, 15, 2, 13, 0, 8, 10, 3, 7, 9, 1, 4, 6, 14},
	{7, 3, 13, 11, 12, 14, 1, 9, 2, 5, 4, 15, 0, 8, 10, 6},
	{9, 5, 2, 10, 4, 15, 7, 0, 14, 11, 6, 3, 8, 13, 12, 1},
	{2, 6, 0, 8, 11, 3, 10, 12, 4, 7, 15, 1, 14, 9, 5, 13},
	{12, 1, 14, 4, 13, 10, 15, 5, 0, 6, 9, 8, 2, 11, 3, 7},
	{13, 7, 12, 3, 1, 9, 14, 11, 5, 15, 8, 2, 6, 10, 4, 0},
	{6, 14, 11, 0, 3, 8, 9, 15, 12, 13, 1, 10, 4, 5, 7, 2},
	{10, 8, 7, 1, 6, 5, 4, 2, 15, 9, 3, 13, 12, 0, 14, 11},
}

// precomputed initial values for the common hash size 256 bit
var hVal256 = [8]uint32{
	0x6b08e647, 0xbb67ae85,
	0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c,
	0x1f83d9ab, 0x5be0cd19,
}
