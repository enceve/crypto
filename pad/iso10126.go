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

func (p *isoPadding) String() string {
	return "ISO-10126-Padding"
}

func (p *isoPadding) BlockSize() int {
	return p.blocksize
}

func (p *isoPadding) Overhead(src []byte) int {
	return generalOverhead(p.blocksize, src)
}

func (p *isoPadding) Pad(src []byte) []byte {
	length := len(src)
	overhead := p.Overhead(src)

	var block []byte
	if length >= p.blocksize {
		block = src[length+overhead-p.blocksize:]
		length = len(block)
	} else {
		block = src
	}

	dst := make([]byte, p.blocksize)
	n, e := p.random.Read(dst)
	if e != nil || n != p.blocksize {
		// if random fails, do a pkcs7 padding
		for i := range dst[p.blocksize-overhead:] {
			dst[i] = byte(overhead)
		}
	} else {
		dst[p.blocksize-1] = byte(overhead)
	}
	return dst
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

	dst := make([]byte, unLen)
	copy(dst, block[:unLen])
	return dst, nil
}

func verifyISO(block []byte, length int) (uint, error) {
	var err error = nil
	padLen := block[length-1]
	if padLen <= 0 || int(padLen) > length {
		err = LengthError(padLen)
	}
	padStart := length - int(padLen)
	return uint(padStart), err
}
