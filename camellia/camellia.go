// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build !386

package camellia

// The camellia non-linear feistel function.
// This version does not attempt to minimize amount of temporary
// variables, but instead explicitly exposes algorithm's parallelism.
// It is therefore most appropriate for platforms with not less than
// about 16 registers. For platforms with less registers (x86) should use
// a special version.
func f(r0, r1, r2, r3 *uint32, k0, k1 uint32) {
	var t0, t1, t2, t3 uint32

	t0 = *r0 ^ k0
	t3 = sbox4_4404[byte(t0)]
	t1 = *r1 ^ k1
	t3 ^= sbox3_3033[byte(t0>>8)]
	t2 = sbox1_1110[byte(t1)]
	t3 ^= sbox2_0222[byte(t0>>16)]
	t2 ^= sbox4_4404[byte(t1>>8)]
	t3 ^= sbox1_1110[byte(t0>>24)]
	t2 ^= t3
	t2 ^= sbox3_3033[byte(t1>>16)]
	*r3 ^= (t3 >> 8) | (t3 << (32 - 8))
	t2 ^= sbox2_0222[byte(t1>>24)]
	*r2 ^= t2
	*r3 ^= t2
}

// Note that n has to be less than 32. Rotations for larger amount
// of bits are achieved by "rotating" order of registers and
// adjusting n accordingly, e.g. RotLeft128(r1,r2,r3,r0,n-32).
func rotl128(r0, r1, r2, r3 *uint32, n uint) {
	t := *r0 >> (32 - n)
	*r0 = (*r0 << n) | (*r1 >> (32 - n))
	*r1 = (*r1 << n) | (*r2 >> (32 - n))
	*r2 = (*r2 << n) | (*r3 >> (32 - n))
	*r3 = (*r3 << n) | t
}
