// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package blake2b

// the core blake2b function using SSE2 SIMD instructions.
func blake2bCoreSSE2(hVal *[8]uint64, ctr *[2]uint64, flag uint64, msg *byte, iv *[8]uint64)

// the core blake2b function taking:
//  - the 8 64 bit chan vales
//  - the 2 64 counters
//  - the final block flag
//  - the message (multiply of the blocksize)
func blake2bCore(hVal *[8]uint64, ctr *[2]uint64, f uint64, msg []byte) {
	length := len(msg)
	for i := 0; i < length; i += BlockSize {
		ctr[0] += BlockSize
		if ctr[0] < BlockSize {
			ctr[1]++
		}
		blake2bCoreSSE2(hVal, ctr, f, &(msg[i]), &iv)
	}
}
