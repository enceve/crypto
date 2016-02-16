package pad

import (
	"errors"
)

type pkcs7Padding int

func (p pkcs7Padding) String() string {
	return "PKCS7-Padding"
}

func (p pkcs7Padding) BlockSize() int {
	return int(p)
}

func (p pkcs7Padding) Overhead(src []byte) int {
	return generalOverhead(p.BlockSize(), src)
}

func (p pkcs7Padding) Pad(src []byte) []byte {
	length := len(src)
	overhead := p.Overhead(src)

	var block []byte
	if length >= p.BlockSize() {
		block = src[length+overhead-p.BlockSize():]
	} else {
		block = src
	}

	dst := make([]byte, p.BlockSize())
	copy(dst, block)
	for i := range dst {
		if i < p.BlockSize()-overhead {
			dst[i] = block[i]
		} else {
			dst[i] = byte(overhead)
		}
	}
	return dst
}

func (p pkcs7Padding) Unpad(src []byte) ([]byte, error) {
	length := len(src)
	if length == 0 || length%p.BlockSize() != 0 {
		return nil, errors.New("src length must be a multiply of the padding blocksize")
	}

	block := src[(length - p.BlockSize()):]
	unLen, err := verifyPkcs7(block, p.BlockSize())
	if err != nil {
		return nil, err
	}

	dst := make([]byte, unLen)
	copy(dst, block[:unLen])
	return dst, nil
}

func verifyPkcs7(block []byte, blocksize int) (int, error) {
	var err error = nil
	padLen := block[blocksize-1]
	if padLen <= 0 || int(padLen) > blocksize {
		err = LengthError(padLen)
	}
	padStart := blocksize - int(padLen)
	for _, b := range block[padStart:] {
		if b != padLen && err == nil {
			err = ByteError(b)
		}
	}
	return int(padStart), err
}
