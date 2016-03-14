// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package chacha

const (
	const0 = 0x61707865
	const1 = 0x3320646e
	const2 = 0x79622d32
	const3 = 0x6b206574
)

// Initialize the cipher with the key and the nonce
func initializeRFC(key, nonce []byte, state *[16]uint32) {
	// The four rfc constants
	state[0] = const0
	state[1] = const1
	state[2] = const2
	state[3] = const3

	// The 256 bit key
	state[4] = uint32(key[0]) | uint32(key[1])<<8 | uint32(key[2])<<16 | uint32(key[3])<<24
	state[5] = uint32(key[4]) | uint32(key[5])<<8 | uint32(key[6])<<16 | uint32(key[7])<<24
	state[6] = uint32(key[8]) | uint32(key[9])<<8 | uint32(key[10])<<16 | uint32(key[11])<<24
	state[7] = uint32(key[12]) | uint32(key[13])<<8 | uint32(key[14])<<16 | uint32(key[15])<<24
	state[8] = uint32(key[16]) | uint32(key[17])<<8 | uint32(key[18])<<16 | uint32(key[19])<<24
	state[9] = uint32(key[20]) | uint32(key[21])<<8 | uint32(key[22])<<16 | uint32(key[23])<<24
	state[10] = uint32(key[24]) | uint32(key[25])<<8 | uint32(key[26])<<16 | uint32(key[27])<<24
	state[11] = uint32(key[28]) | uint32(key[29])<<8 | uint32(key[30])<<16 | uint32(key[31])<<24

	// The counter
	state[12] = Zero

	// The 96 bit nonce
	state[13] = uint32(nonce[0]) | uint32(nonce[1])<<8 | uint32(nonce[2])<<16 | uint32(nonce[3])<<24
	state[14] = uint32(nonce[4]) | uint32(nonce[5])<<8 | uint32(nonce[6])<<16 | uint32(nonce[7])<<24
	state[15] = uint32(nonce[8]) | uint32(nonce[9])<<8 | uint32(nonce[10])<<16 | uint32(nonce[11])<<24
}

// XORKeyStream XORs each byte in the given slice with a byte from the
// cipher's key stream.
func (c *ChachaRFC) XORKeyStream(dst, src []byte) {
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
		core(&(c.stream), &(c.state), DefaultRounds)
		c.state[12]++ // inc. counter
		for i := range c.stream {
			dst[dOff+i] = src[sOff+i] ^ c.stream[i]
		}
		dOff += 64
		sOff += 64
		n -= 64
	}
	if n > 0 {
		c.off = 0
		core(&(c.stream), &(c.state), DefaultRounds)
		c.state[12]++ // inc. counter
		for i := 0; n > 0; i++ {
			dst[dOff+i] = src[sOff+i] ^ c.stream[i]
			c.off++
			n--
		}
	}
}

// Set the counter to an given ctr argument.
func (c *ChachaRFC) Counter(ctr uint32) {
	c.state[12] = ctr
	c.off = 64 // reset the state
}
