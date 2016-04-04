// Use of this source code is governed by a license
// that can be found in the LICENSE file

package skein

const (
	Size1024 = 128 // The max. hash and block size of Skein-1024 in bytes.
	Size512  = 64  // The max. hash and block size of Skein-512 in bytes.
	Size256  = 32  // The max. hash and block of Skein-256 in bytes.
)

// The different parameter types
const (
	keyParam       uint64 = 0
	configParam    uint64 = 4
	publicKeyParam uint64 = 12
	keyIDParam     uint64 = 16
	nonceParam     uint64 = 20
	messageParam   uint64 = 48
	outputParam    uint64 = 63
)

// The first and the last block flags
const (
	firstBlock uint64 = 1 << 62
	lastBlock  uint64 = 1 << 63
)

// The skein schema ID consisting of SHA-3 and the version
var schemaId = []byte{'S', 'H', 'A', '3', 1, 0, 0, 0}

// The output tweak for the skein output function
var outTweak = [3]uint64{8, outputParam<<56 | firstBlock | lastBlock, 8 ^ (outputParam<<56 | firstBlock | lastBlock)}

// Precomputed chain values for Skein-512

var iv512_128 = [8]uint64{
	0xA8BC7BF36FBF9F52, 0x1E9872CEBD1AF0AA, 0x309B1790B32190D3, 0xBCFBB8543F94805C,
	0x0DA61BCD6E31B11B, 0x1A18EBEAD46A32E3, 0xA2CC5B18CE84AA82, 0x6982AB289D46982D,
}

var iv512_160 = [8]uint64{
	0x28B81A2AE013BD91, 0xC2F11668B5BDF78F, 0x1760D8F3F6A56F12, 0x4FB747588239904F,
	0x21EDE07F7EAF5056, 0xD908922E63ED70B8, 0xB8EC76FFECCB52FA, 0x01A47BB8A3F27A6E,
}

var iv512_224 = [8]uint64{
	0xCCD0616248677224, 0xCBA65CF3A92339EF, 0x8CCD69D652FF4B64, 0x398AED7B3AB890B4,
	0x0F59D1B1457D2BD0, 0x6776FE6575D4EB3D, 0x99FBC70E997413E9, 0x9E2CFCCFE1C41EF7,
}

var iv512_256 = [8]uint64{
	0xCCD044A12FDB3E13, 0xE83590301A79A9EB, 0x55AEA0614F816E6F, 0x2A2767A4AE9B94DB,
	0xEC06025E74DD7683, 0xE7A436CDC4746251, 0xC36FBAF9393AD185, 0x3EEDBA1833EDFC13,
}

var iv512_384 = [8]uint64{
	0xA3F6C6BF3A75EF5F, 0xB0FEF9CCFD84FAA4, 0x9D77DD663D770CFE, 0xD798CBF3B468FDDA,
	0x1BC4A6668A0E4465, 0x7ED7D434E5807407, 0x548FC1ACD4EC44D6, 0x266E17546AA18FF8,
}

var iv512_512 = [8]uint64{
	0x4903ADFF749C51CE, 0x0D95DE399746DF03, 0x8FD1934127C79BCE, 0x9A255629FF352CB1,
	0x5DB62599DF6CA7B0, 0xEABE394CA9D5C3F4, 0x991112C71A75B523, 0xAE18A40B660FCC33,
}
