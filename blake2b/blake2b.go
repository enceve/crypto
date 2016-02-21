// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The blake2b package implements the blake2b hash function
// based on the RFC 7693 (https://tools.ietf.org/html/rfc7693).
// This package supports 160, 256, 384 and 512 bit hash values.
// Furthermore the the blake2b MAC, personalized hashing and salting
// are supported.
package blake2b

import (
	"encoding/binary"
	"errors"
	"hash"
)

// the blake2b hash struct
type blake2b struct {
	hVal       [8]uint64
	ctrL, ctrH uint64
	f          uint64
	buf        [BlockSize]byte
	off        byte

	initVal [8]uint64 // initial chain values
	keyed   bool
	key     [BlockSize]byte
	hsize   byte
}

// The parameters for configuring the blake2b hash function.
// All values are optional.
type Params struct {
	// The hash size of blake2b in bytes (default and max. is 64)
	HashSize byte
	// The key for MAC (padded with zeros)
	Key []byte
	// The salt (if < 16 bytes, padded with zeros)
	Salt []byte
	// The personalization string(if < 16 bytes, padded with zeros)
	Person []byte
}

func verifyParams(p *Params) error {
	if p.HashSize > HashSize {
		return errors.New("hash size is too large")
	}
	if p.HashSize < 1 {
		return errors.New("hash size is too small")
	}
	if len(p.Key) > KeySize {
		return errors.New("key is too large")
	}
	if len(p.Salt) > SaltSize {
		return errors.New("salt is too large")
	}
	if len(p.Person) > PersonSize {
		return errors.New("personalization is too large")
	}
	return nil
}

var (
	params512 *Params = &Params{HashSize: HashSize}
	params384 *Params = &Params{HashSize: 48}
	params256 *Params = &Params{HashSize: 32}
	params160 *Params = &Params{HashSize: 20}
)

// Creates a new blake2b hash function from the given
// parameters. If the parameters are invalid, an error
// is returned.
func New(p *Params) (hash.Hash, error) {
	if p == nil {
		p = params512
	} else {
		if p.HashSize == 0 {
			p.HashSize = HashSize
		}
		if err := verifyParams(p); err != nil {
			return nil, err
		}
	}

	b := new(blake2b)
	b.initialize(p)
	return b, nil
}

// Creates a new blake2b hash function for
// 512 bit hash values.
func New512() hash.Hash {
	b := new(blake2b)
	b.initialize(params512)
	return b
}

// Creates a new blake2b hash function for
// 384 bit hash values.
func New384() hash.Hash {
	b := new(blake2b)
	b.initialize(params384)
	return b
}

// Creates a new blake2b hash function for
// 256 bit hash values.
func New256() hash.Hash {
	b := new(blake2b)
	b.initialize(params256)
	return b
}

// Creates a new blake2b hash function for
// 160 bit hash values.
func New160() hash.Hash {
	b := new(blake2b)
	b.initialize(params160)
	return b
}

// Creates a new blake2b hash function configured
// as a MAC function with the given key.
// The size argument specifies the size of the MAC in bytes.
func NewMAC(size int, key []byte) hash.Hash {
	d, err := New(&Params{HashSize: byte(size), Key: key})
	if err != nil {
		panic(err.Error())
	}
	return d
}

func (b *blake2b) BlockSize() int {
	return BlockSize
}

func (b *blake2b) Size() int {
	return int(b.hsize)
}

func (b *blake2b) Write(src []byte) (int, error) {
	n := len(src)
	in := src

	diff := BlockSize - int(b.off)
	if n > diff {
		// process buffer.
		copy(b.buf[b.off:], in[:diff])
		update2b(b, b.buf[:])
		b.off = 0

		in = in[diff:]
	}
	// process full blocks except for the last
	length := len(in)
	if length > BlockSize {
		nn := length - (length % BlockSize)
		if nn == length {
			nn -= BlockSize
		}
		update2b(b, in[:nn])
		in = in[nn:]
	}
	b.off += byte(copy(b.buf[b.off:], in))
	return n, nil
}

func (b *blake2b) Reset() {
	copy(b.hVal[:], b.initVal[:])
	b.ctrL, b.ctrH = 0, 0
	b.f = 0
	for i := range b.buf {
		b.buf[i] = 0
	}
	b.off = 0
	if b.keyed {
		b.Write(b.key[:])
	}
}

func (b *blake2b) Sum(in []byte) []byte {
	if in != nil {
		b.Write(in)
	}
	out := make([]byte, int(b.hsize))
	b.finalize(out)
	b.Reset()
	return out
}

func (b *blake2b) finalize(out []byte) {
	// sub the padding length form the counter
	diff := BlockSize - uint64(b.off)
	if b.ctrL < diff {
		b.ctrH--
	}
	b.ctrL -= diff

	// pad the buffer
	for i := b.off; i < BlockSize; i++ {
		b.buf[i] = 0
	}
	// set the last block flag
	b.f = uint64(0xffffffffffffffff)

	// process last block
	update2b(b, b.buf[:])

	// extract hash
	j := 0
	hRange := (b.hsize-1)/8 + 1
	for _, s := range b.hVal[:hRange] {
		out[j+0] = byte(s >> 0)
		out[j+1] = byte(s >> 8)
		out[j+2] = byte(s >> 16)
		out[j+3] = byte(s >> 24)
		out[j+4] = byte(s >> 32)
		out[j+5] = byte(s >> 40)
		out[j+6] = byte(s >> 48)
		out[j+7] = byte(s >> 56)
		j += 8
	}
}

func (b *blake2b) initialize(conf *Params) {
	// create parameter block.
	var p [BlockSize]byte
	p[0] = conf.HashSize
	p[1] = uint8(len(conf.Key))
	p[2] = 1
	p[3] = 1
	if conf.Salt != nil {
		copy(p[32:], conf.Salt)
	}
	if conf.Person != nil {
		copy(p[48:], conf.Person)
	}

	// initialize hash values
	b.hsize = conf.HashSize
	for i := range iv {
		b.hVal[i] = iv[i] ^ binary.LittleEndian.Uint64(p[i*8:])
	}

	// process key
	if conf.Key != nil {
		copy(b.key[:], conf.Key)
		b.Write(b.key[:])
		b.keyed = true
	}

	// save the initialized state.
	copy(b.initVal[:], b.hVal[:])
}
