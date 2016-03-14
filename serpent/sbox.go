// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package serpent

// The linear transformation of serpent
func linear(v0, v1, v2, v3 uint32) (uint32, uint32, uint32, uint32) {
	v0 = ((v0 << 13) | (v0 >> (32 - 13)))
	v2 = ((v2 << 3) | (v2 >> (32 - 3)))
	v1 = v1 ^ v0 ^ v2
	v3 = v3 ^ v2 ^ (v0 << 3)
	v1 = (v1 << 1) | (v1 >> (32 - 1))
	v3 = (v3 << 7) | (v3 >> (32 - 7))
	v0 = v0 ^ v1 ^ v3
	v2 = v2 ^ v3 ^ (v1 << 7)
	v0 = (v0 << 5) | (v0 >> (32 - 5))
	v2 = (v2 << 22) | (v2 >> (32 - 22))
	return v0, v1, v2, v3
}

// The inverse linear transformation of serpent
func linearInv(v0, v1, v2, v3 uint32) (uint32, uint32, uint32, uint32) {
	v2 = (v2 >> 22) | (v2 << (32 - 22))
	v0 = (v0 >> 5) | (v0 << (32 - 5))
	v2 = v2 ^ v3 ^ (v1 << 7)
	v0 = v0 ^ v1 ^ v3
	v3 = (v3 >> 7) | (v3 << (32 - 7))
	v1 = (v1 >> 1) | (v1 << (32 - 1))
	v3 = v3 ^ v2 ^ (v0 << 3)
	v1 = v1 ^ v0 ^ v2
	v2 = (v2 >> 3) | (v2 << (32 - 3))
	v0 = (v0 >> 13) | (v0 << (32 - 13))
	return v0, v1, v2, v3
}

// The following functions sb0,sb1, ..., sb7 represent the 8 Serpent S-Boxes.
// sb0Inv til sb7Inv are the inverse functions (e.g. sb0Inv is the Inverse to sb0
// and vice versa).
// The S-Boxes differ from the original Serpent definitions. This is for
// optimisation. The functions use the Serpent S-Box improvements form
// Dag Arne Osvik described in http://www.ii.uib.no/~osvik/pub/aes3.pdf.

// S-Box 0
func sb0(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r3 ^= r0
	r4 := r1
	r1 &= r3
	r4 ^= r2
	r1 ^= r0
	r0 |= r3
	r0 ^= r4
	r4 ^= r3
	r3 ^= r2
	r2 |= r1
	r2 ^= r4
	r4 = ^r4
	r4 |= r1
	r1 ^= r3
	r1 ^= r4
	r3 |= r0
	r1 ^= r3
	r4 ^= r3
	return r1, r4, r2, r0
}

// Inverse S-Box 0
func sb0Inv(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r2 = ^r2
	r4 := r1
	r1 |= r0
	r4 = ^r4
	r1 ^= r2
	r2 |= r4
	r1 ^= r3
	r0 ^= r4
	r2 ^= r0
	r0 &= r3
	r4 ^= r0
	r0 |= r1
	r0 ^= r2
	r3 ^= r4
	r2 ^= r1
	r3 ^= r0
	r3 ^= r1
	r2 &= r3
	r4 ^= r2
	return r0, r4, r1, r3
}

// S-Box 1
func sb1(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r0 = ^r0
	r2 = ^r2
	r4 := r0
	r0 &= r1
	r2 ^= r0
	r0 |= r3
	r3 ^= r2
	r1 ^= r0
	r0 ^= r4
	r4 |= r1
	r1 ^= r3
	r2 |= r0
	r2 &= r4
	r0 ^= r1
	r1 &= r2
	r1 ^= r0
	r0 &= r2
	r0 ^= r4
	return r2, r0, r3, r1
}

// Inverse S-Box 1
func sb1Inv(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r4 := r1
	r1 ^= r3
	r3 &= r1
	r4 ^= r2
	r3 ^= r0
	r0 |= r1
	r2 ^= r3
	r0 ^= r4
	r0 |= r2
	r1 ^= r3
	r0 ^= r1
	r1 |= r3
	r1 ^= r0
	r4 = ^r4
	r4 ^= r1
	r1 |= r0
	r1 ^= r0
	r1 |= r4
	r3 ^= r1
	return r4, r0, r3, r2
}

// S-Box 2
func sb2(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r4 := r0
	r0 &= r2
	r0 ^= r3
	r2 ^= r1
	r2 ^= r0
	r3 |= r4
	r3 ^= r1
	r4 ^= r2
	r1 = r3
	r3 |= r4
	r3 ^= r0
	r0 &= r1
	r4 ^= r0
	r1 ^= r3
	r1 ^= r4
	r4 = ^r4
	return r2, r3, r1, r4
}

// Inverse S-Box 2
func sb2Inv(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r2 ^= r3
	r3 ^= r0
	r4 := r3
	r3 &= r2
	r3 ^= r1
	r1 |= r2
	r1 ^= r4
	r4 &= r3
	r2 ^= r3
	r4 &= r0
	r4 ^= r2
	r2 &= r1
	r2 |= r0
	r3 = ^r3
	r2 ^= r3
	r0 ^= r3
	r0 &= r1
	r3 ^= r4
	r3 ^= r0
	return r1, r4, r2, r3
}

// S-Box 3
func sb3(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r4 := r0
	r0 |= r3
	r3 ^= r1
	r1 &= r4
	r4 ^= r2
	r2 ^= r3
	r3 &= r0
	r4 |= r1
	r3 ^= r4
	r0 ^= r1
	r4 &= r0
	r1 ^= r3
	r4 ^= r2
	r1 |= r0
	r1 ^= r2
	r0 ^= r3
	r2 = r1
	r1 |= r3
	r1 ^= r0
	return r1, r2, r3, r4
}

// Inverse S-Box 3
func sb3Inv(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r4 := r2
	r2 ^= r1
	r0 ^= r2
	r4 &= r2
	r4 ^= r0
	r0 &= r1
	r1 ^= r3
	r3 |= r4
	r2 ^= r3
	r0 ^= r3
	r1 ^= r4
	r3 &= r2
	r3 ^= r1
	r1 ^= r0
	r1 |= r2
	r0 ^= r3
	r1 ^= r4
	r0 ^= r1
	return r2, r1, r3, r0
}

// S-Box 4
func sb4(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r1 ^= r3
	r3 = ^r3
	r2 ^= r3
	r3 ^= r0
	r4 := r1
	r1 &= r3
	r1 ^= r2
	r4 ^= r3
	r0 ^= r4
	r2 &= r4
	r2 ^= r0
	r0 &= r1
	r3 ^= r0
	r4 |= r1
	r4 ^= r0
	r0 |= r3
	r0 ^= r2
	r2 &= r3
	r0 = ^r0
	r4 ^= r2
	return r1, r4, r0, r3
}

// Inverse S-Box 4
func sb4Inv(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r4 := r2
	r2 &= r3
	r2 ^= r1
	r1 |= r3
	r1 &= r0
	r4 ^= r2
	r4 ^= r1
	r1 &= r2
	r0 = ^r0
	r3 ^= r4
	r1 ^= r3
	r3 &= r0
	r3 ^= r2
	r0 ^= r1
	r2 &= r0
	r3 ^= r0
	r2 ^= r4
	r2 |= r3
	r3 ^= r0
	r2 ^= r1
	return r0, r3, r2, r4
}

// S-Box 5
func sb5(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r0 ^= r1
	r1 ^= r3
	r3 = ^r3
	r4 := r1
	r1 &= r0
	r2 ^= r3
	r1 ^= r2
	r2 |= r4
	r4 ^= r3
	r3 &= r1
	r3 ^= r0
	r4 ^= r1
	r4 ^= r2
	r2 ^= r0
	r0 &= r3
	r2 = ^r2
	r0 ^= r4
	r4 |= r3
	r2 ^= r4
	return r1, r3, r0, r2
}

// Inverse S-Box 5
func sb5Inv(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r1 = ^r1
	r4 := r3
	r2 ^= r1
	r3 |= r0
	r3 ^= r2
	r2 |= r1
	r2 &= r0
	r4 ^= r3
	r2 ^= r4
	r4 |= r0
	r4 ^= r1
	r1 &= r2
	r1 ^= r3
	r4 ^= r2
	r3 &= r4
	r4 ^= r1
	r3 ^= r4
	r4 = ^r4
	r3 ^= r0
	return r1, r4, r3, r2
}

// S-Box 6
func sb6(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r2 = ^r2
	r4 := r3
	r3 &= r0
	r0 ^= r4
	r3 ^= r2
	r2 |= r4
	r1 ^= r3
	r2 ^= r0
	r0 |= r1
	r2 ^= r1
	r4 ^= r0
	r0 |= r3
	r0 ^= r2
	r4 ^= r3
	r4 ^= r0
	r3 = ^r3
	r2 &= r4
	r2 ^= r3
	return r0, r1, r4, r2
}

// Inverse S-Box 6
func sb6Inv(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r0 ^= r2
	r4 := r2
	r2 &= r0
	r4 ^= r3
	r2 = ^r2
	r3 ^= r1
	r2 ^= r3
	r4 |= r0
	r0 ^= r2
	r3 ^= r4
	r4 ^= r1
	r1 &= r3
	r1 ^= r0
	r0 ^= r3
	r0 |= r2
	r3 ^= r1
	r4 ^= r0
	return r1, r2, r4, r3
}

// S-Box 7
func sb7(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r4 := r1
	r1 |= r2
	r1 ^= r3
	r4 ^= r2
	r2 ^= r1
	r3 |= r4
	r3 &= r0
	r4 ^= r2
	r3 ^= r1
	r1 |= r4
	r1 ^= r0
	r0 |= r4
	r0 ^= r2
	r1 ^= r4
	r2 ^= r1
	r1 &= r0
	r1 ^= r4
	r2 = ^r2
	r2 |= r0
	r4 ^= r2
	return r4, r3, r1, r0
}

// Inverse S-Box 7
func sb7Inv(r0, r1, r2, r3 uint32) (uint32, uint32, uint32, uint32) {
	r4 := r2
	r2 ^= r0
	r0 &= r3
	r4 |= r3
	r2 = ^r2
	r3 ^= r1
	r1 |= r0
	r0 ^= r2
	r2 &= r4
	r3 &= r4
	r1 ^= r2
	r2 ^= r0
	r0 |= r2
	r4 ^= r1
	r0 ^= r3
	r3 ^= r4
	r4 |= r0
	r3 ^= r2
	r4 ^= r2
	return r3, r0, r1, r4
}
