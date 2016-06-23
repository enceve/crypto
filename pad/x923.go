// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package pad

type x923Padding int

func (p x923Padding) BlockSize() int {
	return int(p)
}

func (p x923Padding) Overhead(src []byte) int {
	return overhead(p.BlockSize(), src)
}

func (p x923Padding) Pad(src []byte) []byte {
	overhead := p.Overhead(src)

	dst := make([]byte, overhead)
	dst[overhead-1] = byte(overhead)
	return append(src, dst...)
}

func (p x923Padding) Unpad(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 || length%p.BlockSize() != 0 {
		return nil, notMulOfBlockErr
	}

	block := src[length-p.BlockSize():]
	unLen, err := verifyX923(block, p.BlockSize())
	if err != nil {
		return nil, err
	}
	return src[:(length - p.BlockSize() + unLen)], nil

}

// Verify the X923 padding - NOTICE: not constant time!
func verifyX923(block []byte, blocksize int) (p int, err error) {
	padLen := int(block[blocksize-1])
	if padLen == 0 || int(padLen) > blocksize {
		err = badPadErr
		return
	}

	p = blocksize - int(padLen)
	for _, b := range block[p : blocksize-1] {
		if b != 0 {
			err = badPadErr
		}
	}
	return
}
