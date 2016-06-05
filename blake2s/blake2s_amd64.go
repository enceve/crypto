// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

package blake2s

func blake2sCoreSSE2(hVal *[8]uint32, ctr *[2]uint32, flag uint32, msg *byte, iv *[8]uint32)

func blake2sCore(hVal *[8]uint32, ctr *[2]uint32, f uint32, msg []byte) {
	for i := 0; i < len(msg); i += BlockSize {
		blake2sCoreSSE2(hVal, ctr, f, &msg[i], &iv)
	}
}
