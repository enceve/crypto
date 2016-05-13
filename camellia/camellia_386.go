// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build 386

package camellia

// The camellia non-linear feistel function.
// This is a special x86 version and tries to minimize the
// number of registers. The k0 and k1 vars are reused.
func f(r0, r1, r2, r3 *uint32, k0, k1 uint32) {
	k0 ^= *r0
	k1 ^= *r1

	t := sbox4_4404[byte(k0)]
	t ^= sbox3_3033[byte(k0>>8)]
	t ^= sbox2_0222[byte(k0>>16)]
	t ^= sbox1_1110[byte(k0>>24)]
	*r3 ^= (t >> 8) | (t << (32 - 8))

	k0 = t
	k0 ^= sbox1_1110[byte(k1)]
	k0 ^= sbox4_4404[byte(k1>>8)]
	k0 ^= sbox3_3033[byte(k1>>16)]
	k0 ^= sbox2_0222[byte(k1>>24)]

	*r2 ^= k0
	*r3 ^= k0
}
