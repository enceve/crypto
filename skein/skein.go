// Use of this source code is governed by a license
// that can be found in the LICENSE file

// The skein package implements the skein hash functions
// developed by Niels Ferguson, Stefan Lucks, Bruce Schneier,
// Doug Whiting, Mihir Bellare, Tadayoshi Kohno, Jon Callas,
// and Jesse Walker.
// Skein is based on the Threefish tweakable block cipher
// using Unique Block Iteration (UBI) chaining mode while
// leveraging an optional low-overhead argument-system
// for flexibility.
// Skein was submitted to the SHA-3 challenge.
//
// Skein Variants
//
// There are three skein variants all implemented by
// the skein package:
//     - Skein-256 has a state size of 256 bit (32 byte)
//     - Skein-512 has a state size of 512 bit (64 byte)
//     - Skein-1024 has a state size of 1024 bit (128 byte)
// The max. hash size of a skein variant is the same as
// the state size, but skein can produce hash values of
// any length (limited by the state size).
//
// Using skein
//
// Skein is a very flexible hash function family. It
// can be used for:
// 	- simple, randomized, and personalized hashing
//	- builtin MAC
//	- public key bound hashing for dig. signatures
//	- PRNG
//	- key derivation
//	- en and decryption (stream cipher)
//	- tree hashing
// The API of the skein package only supports:
//	- simple and randomized hashing
//	- builtin MAC
//	- public key bound hashing for dig. signatures
//	- key derivation
// Other functionality may be added in the future.
package skein

import (
	"errors"
	"hash"
)

// The skein-256 hash function with a state size
// of 256 bit. Skein-256 can produce hash values
// from 1 to 32 byte.
type Skein256 struct {
	initVal [4]uint64
	hVal    [5]uint64
	tweak   [3]uint64
	buf     [StateSize256]byte
	off     int
	hsize   int
	msg     bool
}

// The skein-512 hash function with a state size
// of 512 bit. Skein-512 can produce hash values
// from 1 to 64 byte.
// Skein-512 is recommended by the
// skein authors for most use cases.
type Skein512 struct {
	initVal [8]uint64
	hVal    [9]uint64
	tweak   [3]uint64
	buf     [StateSize512]byte
	off     int
	hsize   int
	msg     bool
}

// The skein-1024 hash function with a state size
// of 1024 bit. Skein-1024 can produce hash values
// from 1 to 128 byte.
// Skein-1024 is the very conservative skein variant.
type Skein1024 struct {
	initVal [16]uint64
	hVal    [17]uint64
	tweak   [3]uint64
	buf     [StateSize1024]byte
	off     int
	hsize   int
	msg     bool
}

// The configuration parameters for skein.
// The BlockSize and HashSize fields are required
// and must be set to valid values.
// All other fields are optional and can be nil.
type Params struct {
	BlockSize int    // Required: The block size of the skein variant (32 , 64 or 128)
	HashSize  int    // Required: The hash size - between 1 and the block size
	Key       []byte // Optional: The secret key for MAC
	PublicKey []byte // Optional: The public key for key-bound hashing
	KeyID     []byte // Optional: The key id for key derivation
	Nonce     []byte // Optional: The nonce for randomized hashing
}

// Calculates a 256 bit (32 byte) hash value from the given msg
// with the Skein-512 hash function.
func Sum256(msg []byte) []byte {
	s, err := New512(HashSize256)
	if err != nil {
		// This should never happen
		panic(err)
	}
	s.Write(msg)
	return s.Sum(nil)
}

// Calculates a 384 bit (48 byte) hash value from the given msg
// with the Skein-512 hash function.
func Sum384(msg []byte) []byte {
	s, err := New512(48)
	if err != nil {
		// This should never happen
		panic(err)
	}
	s.Write(msg)
	return s.Sum(nil)
}

// Calculates a 512 bit (64 byte) hash value from the given msg
// with the Skein-512 hash function.
func Sum512(msg []byte) []byte {
	s, err := New512(HashSize512)
	if err != nil {
		// This should never happen
		panic(err)
	}
	s.Write(msg)
	return s.Sum(nil)
}

// Creates a new skein hash function from the given
// parameters. The BlockSize of the params argument
// specifies the skein variant (256, 512 or 1024).
// If the parameters are invalid, an non-nil error
// is returned.
func New(p *Params) (hash.Hash, error) {
	if p == nil {
		return nil, errors.New("nil is invalid params argument")
	}

	if p.BlockSize == StateSize256 {
		if p.HashSize <= 0 || p.HashSize > StateSize256 {
			return nil, errors.New("invalid hash size for skein-256")
		}
		s := new(Skein256)
		s.hsize = p.HashSize
		if p.Key != nil {
			s.addParam(keyParam, p.Key)
		}
		s.addConfig(p.HashSize)
		if p.PublicKey != nil {
			s.addParam(publicKeyParam, p.PublicKey)
		}
		if p.KeyID != nil {
			s.addParam(keyIDParam, p.KeyID)
		}
		if p.Nonce != nil {
			s.addParam(nonceParam, p.Nonce)
		}
		copy(s.initVal[:], s.hVal[:4])

		s.Reset()
		return s, nil
	}
	if p.BlockSize == StateSize512 {
		if p.HashSize <= 0 || p.HashSize > StateSize512 {
			return nil, errors.New("invalid hash size for skein-512")
		}
		s := new(Skein512)
		s.hsize = p.HashSize
		if p.Key != nil {
			s.addParam(keyParam, p.Key)
		}
		s.addConfig(p.HashSize)
		if p.PublicKey != nil {
			s.addParam(publicKeyParam, p.PublicKey)
		}
		if p.KeyID != nil {
			s.addParam(keyIDParam, p.KeyID)
		}
		if p.Nonce != nil {
			s.addParam(nonceParam, p.Nonce)
		}
		copy(s.initVal[:], s.hVal[:8])

		s.Reset()
		return s, nil
	}
	if p.BlockSize == StateSize1024 {
		if p.HashSize <= 0 || p.HashSize > StateSize1024 {
			return nil, errors.New("invalid hash size for skein-1024")
		}
		s := new(Skein1024)
		s.hsize = p.HashSize
		if p.Key != nil {
			s.addParam(keyParam, p.Key)
		}
		s.addConfig(p.HashSize)
		if p.PublicKey != nil {
			s.addParam(publicKeyParam, p.PublicKey)
		}
		if p.KeyID != nil {
			s.addParam(keyIDParam, p.KeyID)
		}
		if p.Nonce != nil {
			s.addParam(nonceParam, p.Nonce)
		}
		copy(s.initVal[:], s.hVal[:16])

		s.Reset()
		return s, nil
	}

	return nil, errors.New("invalid block size for skein")
}

// Creates a new simple skein hash function with the
// given hash and block size. The blocksize argument
// specifies the skein variant (256, 512 or 1024).
// If the hash or block size is invalid, an
// non-nil error is returned.
func NewHash(hashsize int, blocksize int) (hash.Hash, error) {
	switch blocksize {
	default:
		return nil, errors.New("invalid block size for skein")
	case StateSize256:
		return New256(hashsize)
	case StateSize512:
		return New512(hashsize)
	case StateSize1024:
		return New1024(hashsize)
	}
}

// Creates a new skein MAC with the given
// secret key and  hash and block size.
// The blocksize argument specifies the skein
// variant (256, 512 or 1024).
// If the key, the hash size or block size is
// invalid, an non-nil error is returned.
func NewMAC(hashsize int, blocksize int, key []byte) (hash.Hash, error) {
	switch blocksize {
	default:
		return nil, errors.New("invalid block size for skein")
	case StateSize256:
		return NewMAC256(hashsize, key)
	case StateSize512:
		return NewMAC512(hashsize, key)
	case StateSize1024:
		return NewMAC1024(hashsize, key)
	}
}

// Creates a new simple skein-256 hash function
// with the given hash size.
// If the hash size is invalid, an non-nil error
// is returned.
func New256(hashsize int) (*Skein256, error) {
	if hashsize <= 0 || hashsize > StateSize256 {
		return nil, errors.New("invalid hash size for skein-256")
	}
	s := new(Skein256)
	s.hsize = hashsize

	switch hashsize {
	default:
		s.addConfig(hashsize)
		copy(s.initVal[:], s.hVal[:4])
	case 16:
		s.initVal = iv256_128
	case 20:
		s.initVal = iv256_160
	case 28:
		s.initVal = iv256_224
	case StateSize256:
		s.initVal = iv256_256
	}

	s.Reset()
	return s, nil
}

// Creates a new simple skein-512 hash function
// with the given hash size.
// If the hash size is invalid, an non-nil error
// is returned.
func New512(hashsize int) (*Skein512, error) {
	if hashsize <= 0 || hashsize > StateSize512 {
		return nil, errors.New("invalid hash size for skein-512")
	}
	s := new(Skein512)
	s.hsize = hashsize

	switch hashsize {
	default:
		s.addConfig(hashsize)
		copy(s.initVal[:], s.hVal[:8])
	case 16:
		s.initVal = iv512_128
	case 20:
		s.initVal = iv512_160
	case 28:
		s.initVal = iv512_224
	case 32:
		s.initVal = iv512_256
	case 48:
		s.initVal = iv512_384
	case StateSize512:
		s.initVal = iv512_512
	}

	s.Reset()
	return s, nil
}

// Creates a new simple skein-1024 hash function
// with the given hash size.
// If the hash size is invalid, an non-nil error
// is returned.
func New1024(hashsize int) (*Skein1024, error) {
	if hashsize <= 0 || hashsize > StateSize1024 {
		return nil, errors.New("invalid hash size for skein-1024")
	}
	s := new(Skein1024)
	s.hsize = hashsize

	switch hashsize {
	default:
		s.addConfig(hashsize)
		copy(s.initVal[:], s.hVal[:16])
	case 48:
		s.initVal = iv1024_384
	case StateSize512:
		s.initVal = iv1024_512
	case StateSize1024:
		s.initVal = iv1024_1024
	}

	s.Reset()
	return s, nil
}

// Creates a new skein-256 MAC with the
// given secret key and hash size.
// If the hash size is invalid, an
// non-nil error is returned.
func NewMAC256(hashsize int, key []byte) (*Skein256, error) {
	if hashsize <= 0 || hashsize > StateSize256 {
		return nil, errors.New("invalid hash size for skein-256")
	}
	if key == nil {
		return nil, errors.New("nil key is invalid")
	}
	s := new(Skein256)
	s.hsize = hashsize

	s.addParam(keyParam, key)
	s.addConfig(hashsize)
	copy(s.initVal[:], s.hVal[:4])

	s.Reset()
	return s, nil
}

// Creates a new skein-512 MAC with the
// given secret key and hash size.
// If the hash size is invalid, an
// non-nil error is returned.
func NewMAC512(hashsize int, key []byte) (*Skein512, error) {
	if hashsize <= 0 || hashsize > StateSize512 {
		return nil, errors.New("invalid hash size for skein-512")
	}
	if key == nil {
		return nil, errors.New("nil key is invalid")
	}
	s := new(Skein512)
	s.hsize = hashsize

	s.addParam(keyParam, key)
	s.addConfig(hashsize)
	copy(s.initVal[:], s.hVal[:8])

	s.Reset()
	return s, nil
}

// Creates a new skein-1024 MAC with the
// given secret key and hash size.
// If the hash size is invalid, an
// non-nil error is returned.
func NewMAC1024(hashsize int, key []byte) (*Skein1024, error) {
	if hashsize <= 0 || hashsize > StateSize1024 {
		return nil, errors.New("invalid hash size for skein-1024")
	}
	if key == nil {
		return nil, errors.New("nil key is invalid")
	}
	s := new(Skein1024)
	s.hsize = hashsize

	s.addParam(keyParam, key)
	s.addConfig(hashsize)
	copy(s.initVal[:], s.hVal[:16])

	s.Reset()
	return s, nil
}

// Helper functions

// Convert a 32 byte array to 4 64 bit words
func toWords256(msg *[4]uint64, in *[StateSize256]byte) {
	msg[0] = uint64(in[0]) | uint64(in[1])<<8 | uint64(in[2])<<16 | uint64(in[3])<<24 |
		uint64(in[4])<<32 | uint64(in[5])<<40 | uint64(in[6])<<48 | uint64(in[7])<<56

	msg[1] = uint64(in[8]) | uint64(in[9])<<8 | uint64(in[10])<<16 | uint64(in[11])<<24 |
		uint64(in[12])<<32 | uint64(in[13])<<40 | uint64(in[14])<<48 | uint64(in[15])<<56

	msg[2] = uint64(in[16]) | uint64(in[17])<<8 | uint64(in[18])<<16 | uint64(in[19])<<24 |
		uint64(in[20])<<32 | uint64(in[21])<<40 | uint64(in[22])<<48 | uint64(in[23])<<56

	msg[3] = uint64(in[24]) | uint64(in[25])<<8 | uint64(in[26])<<16 | uint64(in[27])<<24 |
		uint64(in[28])<<32 | uint64(in[29])<<40 | uint64(in[30])<<48 | uint64(in[31])<<56
}

// Convert a 64 byte array to 8 64 bit words
func toWords512(msg *[8]uint64, in *[StateSize512]byte) {
	msg[0] = uint64(in[0]) | uint64(in[1])<<8 | uint64(in[2])<<16 | uint64(in[3])<<24 |
		uint64(in[4])<<32 | uint64(in[5])<<40 | uint64(in[6])<<48 | uint64(in[7])<<56

	msg[1] = uint64(in[8]) | uint64(in[9])<<8 | uint64(in[10])<<16 | uint64(in[11])<<24 |
		uint64(in[12])<<32 | uint64(in[13])<<40 | uint64(in[14])<<48 | uint64(in[15])<<56

	msg[2] = uint64(in[16]) | uint64(in[17])<<8 | uint64(in[18])<<16 | uint64(in[19])<<24 |
		uint64(in[20])<<32 | uint64(in[21])<<40 | uint64(in[22])<<48 | uint64(in[23])<<56

	msg[3] = uint64(in[24]) | uint64(in[25])<<8 | uint64(in[26])<<16 | uint64(in[27])<<24 |
		uint64(in[28])<<32 | uint64(in[29])<<40 | uint64(in[30])<<48 | uint64(in[31])<<56

	msg[4] = uint64(in[32]) | uint64(in[33])<<8 | uint64(in[34])<<16 | uint64(in[35])<<24 |
		uint64(in[36])<<32 | uint64(in[37])<<40 | uint64(in[38])<<48 | uint64(in[39])<<56

	msg[5] = uint64(in[40]) | uint64(in[41])<<8 | uint64(in[42])<<16 | uint64(in[43])<<24 |
		uint64(in[44])<<32 | uint64(in[45])<<40 | uint64(in[46])<<48 | uint64(in[47])<<56

	msg[6] = uint64(in[48]) | uint64(in[49])<<8 | uint64(in[50])<<16 | uint64(in[51])<<24 |
		uint64(in[52])<<32 | uint64(in[53])<<40 | uint64(in[54])<<48 | uint64(in[55])<<56

	msg[7] = uint64(in[56]) | uint64(in[57])<<8 | uint64(in[58])<<16 | uint64(in[59])<<24 |
		uint64(in[60])<<32 | uint64(in[61])<<40 | uint64(in[62])<<48 | uint64(in[63])<<56
}

// Convert a 128 byte array to 16 64 bit words
func toWords1024(msg *[16]uint64, in *[StateSize1024]byte) {
	msg[0] = uint64(in[0]) | uint64(in[1])<<8 | uint64(in[2])<<16 | uint64(in[3])<<24 |
		uint64(in[4])<<32 | uint64(in[5])<<40 | uint64(in[6])<<48 | uint64(in[7])<<56

	msg[1] = uint64(in[8]) | uint64(in[9])<<8 | uint64(in[10])<<16 | uint64(in[11])<<24 |
		uint64(in[12])<<32 | uint64(in[13])<<40 | uint64(in[14])<<48 | uint64(in[15])<<56

	msg[2] = uint64(in[16]) | uint64(in[17])<<8 | uint64(in[18])<<16 | uint64(in[19])<<24 |
		uint64(in[20])<<32 | uint64(in[21])<<40 | uint64(in[22])<<48 | uint64(in[23])<<56

	msg[3] = uint64(in[24]) | uint64(in[25])<<8 | uint64(in[26])<<16 | uint64(in[27])<<24 |
		uint64(in[28])<<32 | uint64(in[29])<<40 | uint64(in[30])<<48 | uint64(in[31])<<56

	msg[4] = uint64(in[32]) | uint64(in[33])<<8 | uint64(in[34])<<16 | uint64(in[35])<<24 |
		uint64(in[36])<<32 | uint64(in[37])<<40 | uint64(in[38])<<48 | uint64(in[39])<<56

	msg[5] = uint64(in[40]) | uint64(in[41])<<8 | uint64(in[42])<<16 | uint64(in[43])<<24 |
		uint64(in[44])<<32 | uint64(in[45])<<40 | uint64(in[46])<<48 | uint64(in[47])<<56

	msg[6] = uint64(in[48]) | uint64(in[49])<<8 | uint64(in[50])<<16 | uint64(in[51])<<24 |
		uint64(in[52])<<32 | uint64(in[53])<<40 | uint64(in[54])<<48 | uint64(in[55])<<56

	msg[7] = uint64(in[56]) | uint64(in[57])<<8 | uint64(in[58])<<16 | uint64(in[59])<<24 |
		uint64(in[60])<<32 | uint64(in[61])<<40 | uint64(in[62])<<48 | uint64(in[63])<<56

	msg[8] = uint64(in[64]) | uint64(in[65])<<8 | uint64(in[66])<<16 | uint64(in[67])<<24 |
		uint64(in[68])<<32 | uint64(in[69])<<40 | uint64(in[70])<<48 | uint64(in[71])<<56

	msg[9] = uint64(in[72]) | uint64(in[73])<<8 | uint64(in[74])<<16 | uint64(in[75])<<24 |
		uint64(in[76])<<32 | uint64(in[77])<<40 | uint64(in[78])<<48 | uint64(in[79])<<56

	msg[10] = uint64(in[80]) | uint64(in[81])<<8 | uint64(in[82])<<16 | uint64(in[83])<<24 |
		uint64(in[84])<<32 | uint64(in[85])<<40 | uint64(in[86])<<48 | uint64(in[87])<<56

	msg[11] = uint64(in[88]) | uint64(in[89])<<8 | uint64(in[90])<<16 | uint64(in[91])<<24 |
		uint64(in[92])<<32 | uint64(in[93])<<40 | uint64(in[94])<<48 | uint64(in[95])<<56

	msg[12] = uint64(in[96]) | uint64(in[97])<<8 | uint64(in[98])<<16 | uint64(in[99])<<24 |
		uint64(in[100])<<32 | uint64(in[101])<<40 | uint64(in[102])<<48 | uint64(in[103])<<56

	msg[13] = uint64(in[104]) | uint64(in[105])<<8 | uint64(in[106])<<16 | uint64(in[107])<<24 |
		uint64(in[108])<<32 | uint64(in[109])<<40 | uint64(in[110])<<48 | uint64(in[111])<<56

	msg[14] = uint64(in[112]) | uint64(in[113])<<8 | uint64(in[114])<<16 | uint64(in[115])<<24 |
		uint64(in[116])<<32 | uint64(in[117])<<40 | uint64(in[118])<<48 | uint64(in[119])<<56

	msg[15] = uint64(in[120]) | uint64(in[121])<<8 | uint64(in[122])<<16 | uint64(in[123])<<24 |
		uint64(in[124])<<32 | uint64(in[125])<<40 | uint64(in[126])<<48 | uint64(in[127])<<56
}

// Increment the tweak by the ctr argument
// Skein can consume messages up to 2^96 -1 bytes
func incTweak(tweak *[3]uint64, ctr uint64) {
	t0 := tweak[0]
	tweak[0] += ctr
	if tweak[0] < t0 {
		t1 := tweak[1]
		tweak[1] = (t1 & 0xFFFFFFFF00000000) | ((t1 + 1) & 0x00000000FFFFFFFF)
	}
}

// Xor`s the original message with output of the
// threefish encryption (msg)
func xor256(hVal *[5]uint64, message, msg *[4]uint64) {
	hVal[0] = message[0] ^ msg[0]
	hVal[1] = message[1] ^ msg[1]
	hVal[2] = message[2] ^ msg[2]
	hVal[3] = message[3] ^ msg[3]
}

// Xor`s the original message with output of the
// threefish encryption (msg)
func xor512(hVal *[9]uint64, message, msg *[8]uint64) {
	hVal[0] = message[0] ^ msg[0]
	hVal[1] = message[1] ^ msg[1]
	hVal[2] = message[2] ^ msg[2]
	hVal[3] = message[3] ^ msg[3]
	hVal[4] = message[4] ^ msg[4]
	hVal[5] = message[5] ^ msg[5]
	hVal[6] = message[6] ^ msg[6]
	hVal[7] = message[7] ^ msg[7]
}

// Xor`s the original message with output of the
// threefish encryption (msg)
func xor1024(hVal *[17]uint64, message, msg *[16]uint64) {
	hVal[0] = message[0] ^ msg[0]
	hVal[1] = message[1] ^ msg[1]
	hVal[2] = message[2] ^ msg[2]
	hVal[3] = message[3] ^ msg[3]
	hVal[4] = message[4] ^ msg[4]
	hVal[5] = message[5] ^ msg[5]
	hVal[6] = message[6] ^ msg[6]
	hVal[7] = message[7] ^ msg[7]
	hVal[8] = message[8] ^ msg[8]
	hVal[9] = message[9] ^ msg[9]
	hVal[10] = message[10] ^ msg[10]
	hVal[11] = message[11] ^ msg[11]
	hVal[12] = message[12] ^ msg[12]
	hVal[13] = message[13] ^ msg[13]
	hVal[14] = message[14] ^ msg[14]
	hVal[15] = message[15] ^ msg[15]
}
