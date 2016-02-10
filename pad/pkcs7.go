package pad

type pkcs7Padding uint

func (p pkcs7Padding) Overhead(block []byte, size int) uint {
	if size <= 0 || size > 255 {
		panic("pad: illegal blocksize - size must between 0 and 256")
	}
	length := len(block)
	if length > size {
		panic("pad: len of block must be smaller than or equal to the blocksize")
	}
	if length == size {
		return uint(2 * size)
	} else {
		return uint(size - length)
	}
}

func (p pkcs7Padding) Pad(block []byte, size int) []byte {
	if size <= 0 || size > 255 {
		panic("pad: illegal blocksize - size must between 0 and 256")
	}
	length := len(block)
	if length > size {
		panic("pad: len of block must be smaller than or equal to the blocksize")
	}
	var dst []byte
	var padByte byte
	var padLen int
	if length == size {
		dst = make([]byte, 2*size)
		padByte = byte(length)
		padLen = length
	} else {
		dst = make([]byte, size)
		padByte = byte(size - length)
		padLen = length
	}
	copy(dst, block)
	for i := int(padLen); i < len(dst); i++ {
		dst[i] = padByte
	}
	return dst
}

func (p pkcs7Padding) Unpad(block []byte, size int) ([]byte, error) {
	if size <= 0 || size > 255 {
		panic("pad: illegal blocksize - size must between 0 and 256")
	}
	length := len(block)
	if length != size {
		panic("pad: len of block must be equal to the blocksize")
	}
	unLen, err := verifyPkcs7(block, length)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, unLen)
	copy(dst, block[:unLen])
	return dst, nil
}

func verifyPkcs7(block []byte, length int) (uint, error) {
	var err error = nil
	padLen := block[length-1]
	if padLen == 0 || int(padLen) > length {
		err = LengthError(padLen)
	}
	padStart := length - int(padLen)
	for i := padStart; i < length-1; i++ {
		if block[i] != padLen && err == nil {
			err = ByteError(block[i])
		}
	}
	return uint(padStart), err
}
