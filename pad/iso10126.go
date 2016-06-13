// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package pad

import (
	"errors"
	"io"
)

type isoPadding struct {
	blocksize int
	random    io.Reader
}

func (p *isoPadding) BlockSize() int {
	return p.blocksize
}

func (p *isoPadding) Overhead(src []byte) int {
	return overhead(p.blocksize, src)
}

func (p *isoPadding) Pad(src []byte) []byte {
	overhead := p.Overhead(src)

	dst := make([]byte, overhead)
	n, e := io.ReadFull(p.random, dst)
	if e != nil || n != overhead {
		// if random fails, do a pkcs7 padding
		for i := range dst {
			dst[i] = byte(overhead)
		}
	}

	dst[overhead-1] = byte(overhead)
	return append(src, dst...)
}

func (p *isoPadding) Unpad(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 || length%p.blocksize != 0 {
		return nil, errors.New("src length must be a multiply of the padding blocksize")
	}

	block := src[length-p.blocksize:]
	unLen, err := verifyISO(block, p.blocksize)
	if err != nil {
		return nil, err
	}

	return src[:(length - p.BlockSize() + unLen)], nil
}

// verify the iso10126 padding
func verifyISO(block []byte, length int) (p int, err error) {
	padLen := block[length-1]
	if padLen <= 0 || int(padLen) > length {
		err = LengthError(padLen)
	}
	p = length - int(padLen)
	return
}
