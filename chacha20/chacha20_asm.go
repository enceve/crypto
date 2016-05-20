// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build amd64

package chacha20

func chachaCore(dst *[64]byte, state *[16]uint32, rounds int)
