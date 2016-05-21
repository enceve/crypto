// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build amd64

package chacha20

// Computes ChaCha20|r keystream. The keystream is writen to dst.
// The state is NOT changed/updated
func chachaCore(dst *[64]byte, state *[16]uint32, rounds int)

// Computes ChaCha20|r keystream. The keystream is xor'd with src and writen to dst.
// The state is NOT changed/updated.
func chachaCoreXOR(dst *byte, src *byte, state *[16]uint32, rounds int)

// Computes 128 byte of the ChaCha20|r keystream. The keystream is xor'd with src and writen to dst.
// The state is changed/updated. The function writes n128 * 128 bytes to dst.
func chachaCoreXOR128(dst *byte, src *byte, n128 int, state *[16]uint32, rounds int)

// Amd64 versions of genericXORKeyStream and XORKeyStream functions

// genericXORKeyStream produces the ChaCha20/x keystream, xor's it with src and writes the
// result to dst. The rounds argument determines the number of chacha-rounds
// (common are 20, 12 and 8) .
func genericXORKeyStream(dst, src []byte, key *[32]byte, nonce *[12]byte, ctr uint32, rounds int) {
	length := len(src)
	if len(dst) < length {
		panic("dst buffer is to small")
	}
	var state [16]uint32
	var buf [64]byte

	initialize(key, nonce, &state)
	state[12] = ctr

	i := 0
	n := length - (length % 128)
	if n > 0 {
		chachaCoreXOR128(&dst[0], &src[0], n, &state, rounds)
		length -= n
		i += n
	}
	if length >= 64 {
		chachaCoreXOR(&dst[i], &src[i], &state, rounds)
		state[12]++ // inc. counter
		length -= 64
		i += 64
	}
	if length > 0 {
		chachaCore(&buf, &state, rounds)
		for j, v := range buf[:length] {
			dst[i+j] = src[i+j] ^ v
		}
	}
}

func (c *chacha20) XORKeyStream(dst, src []byte) {
	length := len(src)
	if len(dst) < length {
		panic("dst buffer to small")
	}
	if c.off > 0 {
		left := 64 - c.off
		if left > length {
			left = length
		}
		for i := 0; i < left; i++ {
			dst[i] = src[i] ^ c.stream[c.off+i]
		}
		src = src[left:]
		dst = dst[left:]
		length -= left
		c.off += left
		if c.off == 64 {
			c.off = 0
		}
	}

	i := 0
	n := length - (length % 128)
	if n > 0 {
		chachaCoreXOR128(&dst[0], &src[0], n, &(c.state), 20)
		length -= n
		i += n
	}
	if length >= 64 {
		chachaCoreXOR(&dst[i], &src[i], &(c.state), 20)
		c.state[12]++ // inc. counter
		length -= 64
		i += 64
	}
	if length > 0 {
		chachaCore(&(c.stream), &(c.state), 20)
		c.state[12]++ // inc. counter
		for j, v := range c.stream[:length] {
			dst[i+j] = src[i+j] ^ v
		}
		c.off += length
	}
}
