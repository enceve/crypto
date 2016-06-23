// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package pad

type pkcs7Padding int

func (p pkcs7Padding) BlockSize() int {
	return int(p)
}

func (p pkcs7Padding) Overhead(src []byte) int {
	return overhead(p.BlockSize(), src)
}

func (p pkcs7Padding) Pad(src []byte) []byte {
	overhead := p.Overhead(src)

	dst := make([]byte, overhead)
	for i := range dst {
		dst[i] = byte(overhead)
	}
	return append(src, dst...)
}

func (p pkcs7Padding) Unpad(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 || length%p.BlockSize() != 0 {
		return nil, notMulOfBlockErr
	}

	block := src[(length - p.BlockSize()):]
	unLen, err := verifyPkcs7(block, p.BlockSize())
	if err != nil {
		return nil, err
	}
	return src[:(length - p.BlockSize() + unLen)], nil
}

// Verify the PKCS7 padding - NOTICE: not constant time!
func verifyPkcs7(block []byte, blocksize int) (p int, err error) {
	padLen := block[blocksize-1]
	if padLen == 0 || int(padLen) > blocksize {
		err = badPadErr
		return
	}

	p = blocksize - int(padLen)
	for _, b := range block[p:] {
		if b != padLen {
			err = badPadErr
		}
	}
	return
}
