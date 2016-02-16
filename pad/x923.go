package pad

import (
	"errors"
)

type x923Padding int

func (p x923Padding) String() string {
	return "ANSI-X923-Padding"
}

func (p x923Padding) BlockSize() int {
	return int(p)
}

func (p x923Padding) Overhead(src []byte) int {
	return generalOverhead(p.BlockSize(), src)
}

func (p x923Padding) Pad(src []byte) []byte {
	length := len(src)
	overhead := p.Overhead(src)

	var block []byte
	if length >= int(p) {
		block = src[length+overhead-p.BlockSize():]
		length = len(block)
	} else {
		block = src
	}

	dst := make([]byte, int(p))
	copy(dst, block)
	dst[int(p)-1] = byte(overhead)
	return dst
}

func (p x923Padding) Unpad(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 || length%p.BlockSize() != 0 {
		return nil, errors.New("src length must be a multiply of the padding blocksize")
	}

	block := src[length-p.BlockSize():]
	unLen, err := verifyX923(block, p.BlockSize())
	if err != nil {
		return nil, err
	}

	dst := make([]byte, unLen)
	copy(dst, block[:unLen])
	return dst, nil
}

func verifyX923(block []byte, blocksize int) (uint, error) {
	var err error = nil
	padLen := block[blocksize-1]
	if padLen <= 0 || int(padLen) > blocksize {
		err = LengthError(padLen)
	}
	padStart := blocksize - int(padLen)
	for _, b := range block[padStart : blocksize-1] {
		if b != 0 && err == nil {
			err = ByteError(b)
		}
	}
	return uint(padStart), err
}
