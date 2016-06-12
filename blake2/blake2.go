// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// Package blake2 implements the both hash functions BLAKE2b and
// BLAKE2s described in RFC 7693.
// RFC 7693 only specifies BLAKE2 as pure hash and mac function,
// but BLAKE2 supports also salted (randomized) and personalized
// hashing. These features are implemented in the blake2b package
// for BLAKE2b and in the blake2s package for BLAKE2s.
package blake2

import (
	"github.com/enceve/crypto/blake2/blake2b"
	"github.com/enceve/crypto/blake2/blake2s"
)

var (
	hVal512 = [8]uint64{
		0x6a09e667f2bdc948, 0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f,
		0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
	}
	hVal256b = [8]uint64{
		0x6a09e667f2bdc928, 0xbb67ae8584caa73b,
		0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f,
		0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
	}
	hVal256s = [8]uint32{
		0x6b08e647, 0xbb67ae85,
		0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c,
		0x1f83d9ab, 0x5be0cd19,
	}
	hVal160s = [8]uint32{
		0x6b08e673, 0xbb67ae85,
		0x3c6ef372, 0xa54ff53a,
		0x510e527f, 0x9b05688c,
		0x1f83d9ab, 0x5be0cd19,
	}
)

// Sum512 computes the 512 bit BLAKE2b checksum (or MAC if a key is specified)
// of msg and saves the sum in out. The key is optional and can be nil.
func Sum512(out *[64]byte, msg, key []byte) {
	var (
		hVal  [8]uint64
		ctr   [2]uint64
		block [blake2b.BlockSize]byte
		off   int
	)
	hVal = hVal512

	if k := len(key); k > 0 {
		hVal[0] ^= uint64(k) << 8 // mixin key-length

		copy(block[:], key)
		off = blake2b.BlockSize
		if len(msg) > 0 {
			blake2b.Core(&hVal, &ctr, blake2b.MsgFlag, block[:])
			off = 0
		}
	}

	if length := len(msg); length > blake2b.BlockSize {
		n := length & (^(blake2b.BlockSize - 1)) // length -= (length % BlockSize)
		if length == n {
			n -= blake2b.BlockSize
		}
		blake2b.Core(&hVal, &ctr, blake2b.MsgFlag, msg[:n])
		msg = msg[n:]
	}

	if len(msg) > 0 {
		off += copy(block[:], msg)
	}

	blake2b.ExtractHash(out, &hVal, &ctr, &block, off)
}

// Sum256b computes the 256 bit BLAKE2b checksum (or MAC if a key is specified)
// of msg and saves the sum in out. The key is optional and can be nil.
func Sum256b(out *[32]byte, msg, key []byte) {
	var (
		hVal  [8]uint64
		ctr   [2]uint64
		block [blake2b.BlockSize]byte
		off   int

		out512 [64]byte
	)
	hVal = hVal256b

	if k := len(key); k > 0 {
		hVal[0] ^= uint64(k) << 8 // mixin key-length

		copy(block[:], key)
		off = blake2b.BlockSize
		if len(msg) > 0 {
			blake2b.Core(&hVal, &ctr, blake2b.MsgFlag, block[:])
			off = 0
		}
	}

	if length := len(msg); length > blake2b.BlockSize {
		n := length & (^(blake2b.BlockSize - 1)) // length -= (length % BlockSize)
		if length == n {
			n -= blake2b.BlockSize
		}
		blake2b.Core(&hVal, &ctr, blake2b.MsgFlag, msg[:n])
		msg = msg[n:]
	}

	if len(msg) > 0 {
		off += copy(block[:], msg)
	}

	blake2b.ExtractHash(&out512, &hVal, &ctr, &block, off)
	copy(out[:], out512[:32])
}

// Sum256s computes the 256 bit BLAKE2s checksum (or MAC if a key is specified)
// of msg and saves the sum in out. The key is optional and can be nil.
func Sum256s(out *[32]byte, msg, key []byte) {
	var (
		hVal  [8]uint32
		ctr   [2]uint32
		block [blake2s.BlockSize]byte
		off   int
	)
	hVal = hVal256s

	if k := len(key); k > 0 {
		hVal[0] ^= uint32(k) << 8 // mixin key-length

		copy(block[:], key)
		off = blake2s.BlockSize
		if len(msg) > 0 {
			blake2s.Core(&hVal, &ctr, blake2s.MsgFlag, block[:])
			off = 0
		}
	}

	if length := len(msg); length > blake2s.BlockSize {
		n := length & (^(blake2s.BlockSize - 1)) // length -= (length % BlockSize)
		if length == n {
			n -= blake2s.BlockSize
		}
		blake2s.Core(&hVal, &ctr, blake2s.MsgFlag, msg[:n])
		msg = msg[n:]
	}

	if len(msg) > 0 {
		off += copy(block[:], msg)
	}

	blake2s.ExtractHash(out, &hVal, &ctr, &block, off)
}

// Sum160s computes the 160 bit BLAKE2s checksum (or MAC if a key is specified)
// of msg and saves the sum in out. The key is optional and can be nil.
func Sum160s(out *[20]byte, msg, key []byte) {
	var (
		hVal  [8]uint32
		ctr   [2]uint32
		block [blake2s.BlockSize]byte
		off   int

		out256 [32]byte
	)
	hVal = hVal160s

	if k := len(key); k > 0 {
		hVal[0] ^= uint32(k) << 8 // mixin key-length

		copy(block[:], key)
		off = blake2s.BlockSize
		if len(msg) > 0 {
			blake2s.Core(&hVal, &ctr, blake2s.MsgFlag, block[:])
			off = 0
		}
	}

	if length := len(msg); length > blake2s.BlockSize {
		n := length & (^(blake2s.BlockSize - 1)) // length -= (length % BlockSize)
		if length == n {
			n -= blake2s.BlockSize
		}
		blake2s.Core(&hVal, &ctr, blake2s.MsgFlag, msg[:n])
		msg = msg[n:]
	}

	if len(msg) > 0 {
		off += copy(block[:], msg)
	}

	blake2s.ExtractHash(&out256, &hVal, &ctr, &block, off)
	copy(out[:], out256[:20])
}
