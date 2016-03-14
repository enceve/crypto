// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package chacha

// XORKeyStream XORs each byte in the given slice with a byte from the
// cipher's key stream.
func (c *Chacha) XORKeyStream(dst, src []byte) {
	n := len(src)
	if len(dst) < n {
		panic("output buffer to small")
	}
	dOff, sOff := 0, 0
	if c.off < 64 {
		for n > 0 && c.off < 64 {
			dst[dOff] = src[sOff] ^ c.stream[c.off]
			dOff, sOff, c.off = dOff+1, sOff+1, c.off+1
			n--
		}
	}
	for n >= 64 {
		core(&(c.stream), &(c.state), c.rounds)
		count(&(c.state))
		for i, v := range c.stream {
			dst[dOff+i] = src[sOff+i] ^ v
		}
		dOff += 64
		sOff += 64
		n -= 64
	}
	if n > 0 {
		c.off = 0
		core(&(c.stream), &(c.state), c.rounds)
		count(&(c.state))
		for i := 0; n > 0; i++ {
			dst[dOff+i] = src[sOff+i] ^ c.stream[i]
			c.off++
			n--
		}
	}
}

// Initialize the cipher with the key and the nonce
func initialize(key, nonce []byte, state *[16]uint32) {
	keyOff := 0
	constant := tau
	if len(key) == 32 {
		keyOff = 16
		constant = sigma
	}
	// the key size depended constant
	state[0] = uint32(constant[0]) | uint32(constant[1])<<8 | uint32(constant[2])<<16 | uint32(constant[3])<<24
	state[1] = uint32(constant[4]) | uint32(constant[5])<<8 | uint32(constant[6])<<16 | uint32(constant[7])<<24
	state[2] = uint32(constant[8]) | uint32(constant[9])<<8 | uint32(constant[10])<<16 | uint32(constant[11])<<24
	state[3] = uint32(constant[12]) | uint32(constant[13])<<8 | uint32(constant[14])<<16 | uint32(constant[15])<<24

	// the first 16 byte of the key
	state[4] = uint32(key[0]) | uint32(key[1])<<8 | uint32(key[2])<<16 | uint32(key[3])<<24
	state[5] = uint32(key[4]) | uint32(key[5])<<8 | uint32(key[6])<<16 | uint32(key[7])<<24
	state[6] = uint32(key[8]) | uint32(key[9])<<8 | uint32(key[10])<<16 | uint32(key[11])<<24
	state[7] = uint32(key[12]) | uint32(key[13])<<8 | uint32(key[14])<<16 | uint32(key[15])<<24

	// the next 16 byte of the key
	// if the key size is 128 bit,
	// use the first 16 bytes again
	state[8] = uint32(key[keyOff]) | uint32(key[keyOff+1])<<8 | uint32(key[keyOff+2])<<16 | uint32(key[keyOff+3])<<24
	state[9] = uint32(key[keyOff+4]) | uint32(key[keyOff+5])<<8 | uint32(key[keyOff+6])<<16 | uint32(key[keyOff+7])<<24
	state[10] = uint32(key[keyOff+8]) | uint32(key[keyOff+9])<<8 | uint32(key[keyOff+10])<<16 | uint32(key[keyOff+11])<<24
	state[11] = uint32(key[keyOff+12]) | uint32(key[keyOff+13])<<8 | uint32(key[keyOff+14])<<16 | uint32(key[keyOff+15])<<24

	// the 64 bit counter set to 0
	state[12] = 0
	state[13] = 0

	// the 64 bit nonce
	state[14] = uint32(nonce[0]) | uint32(nonce[1])<<8 | uint32(nonce[2])<<16 | uint32(nonce[3])<<24
	state[15] = uint32(nonce[4]) | uint32(nonce[5])<<8 | uint32(nonce[6])<<16 | uint32(nonce[7])<<24
}

// Increment the counter by one
func count(state *[16]uint32) {
	state[12]++
	if state[12] == 0 {
		state[13]++
	}
}

// Set the counter to the given ctr argument.
func (c *Chacha) Counter(ctr uint64) {
	c.state[12] = uint32(ctr >> 32)
	c.state[13] = uint32(ctr)
	c.off = 64 // reset state
}
