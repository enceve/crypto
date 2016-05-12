// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package blake2b

import "errors"

// Verify blake2b config parameters
func verifyParams(p *Params) error {
	if p.HashSize < 1 || p.HashSize > Size {
		p.HashSize = Size
	}
	if len(p.Key) > keySize {
		return errors.New("key is too large")
	}
	if len(p.Salt) > saltSize {
		return errors.New("salt is too large")
	}
	return nil
}

// Initialize the hash function with the given
// parameters
func (h *hashFunc) initialize(conf *Params) {
	// create parameter block.
	var p [BlockSize]byte
	p[0] = byte(conf.HashSize)
	p[1] = uint8(len(conf.Key))
	p[2] = 1
	p[3] = 1
	if conf.Salt != nil {
		copy(p[32:], conf.Salt)
	}

	// initialize hash values
	h.hsize = conf.HashSize
	for i := range iv {
		j := i * 8
		pv := uint64(p[j+0]) | uint64(p[j+1])<<8 | uint64(p[j+2])<<16 | uint64(p[j+3])<<24 |
			uint64(p[j+4])<<32 | uint64(p[j+5])<<40 | uint64(p[j+6])<<48 | uint64(p[j+7])<<56
		h.hVal[i] = iv[i] ^ pv
	}

	// process key
	if conf.Key != nil {
		copy(h.key[:], conf.Key)
		h.Write(h.key[:])
		h.keyed = true
	}

	// save the initialized state.
	h.initVal = h.hVal
}

// Finalize the hash by adding padding bytes (if necessary)
// and extract the hash to a byte array.
func (h *hashFunc) finalize(out *[Size]byte) {
	// sub the padding length form the counter
	diff := BlockSize - uint64(h.off)
	if h.ctr[0] < diff {
		h.ctr[1]--
	}
	h.ctr[0] -= diff

	// pad the buffer
	for i := h.off; i < BlockSize; i++ {
		h.buf[i] = 0
	}

	// process last block
	blake2bCore(&(h.hVal), &(h.ctr), lastBlock, h.buf[:])

	// extract hash
	j := 0
	for _, s := range h.hVal {
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
