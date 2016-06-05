// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package blake2s

import "errors"

// Verify BLAKE2s config parameters
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
		j := i * 4
		pv := uint32(p[j+0]) | uint32(p[j+1])<<8 | uint32(p[j+2])<<16 | uint32(p[j+3])<<24
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
func finalize(out *[Size]byte, hVal *[8]uint32, ctr *[2]uint32, buf *[BlockSize]byte, off int) {
	// sub the padding length form the counter
	diff := BlockSize - uint32(off)
	if ctr[0] < diff {
		ctr[1]--
	}
	ctr[0] -= diff

	// pad the buffer
	for i := off; i < BlockSize; i++ {
		buf[i] = 0
	}

	// process last block
	blake2sCore(hVal, ctr, lastBlock, buf[:])

	// extract hash
	j := 0
	for _, s := range hVal {
		out[j+0] = byte(s >> 0)
		out[j+1] = byte(s >> 8)
		out[j+2] = byte(s >> 16)
		out[j+3] = byte(s >> 24)
		j += 4
	}
}
