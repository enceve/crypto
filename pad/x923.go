package pad

type x923Padding uint

func (p x923Padding) Overhead(block []byte, size int) uint {
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

func (p x923Padding) Pad(block []byte, size int) []byte {
	if size <= 0 || size > 255 {
		panic("pad: illegal blocksize - size must between 0 and 256")
	}
	length := len(block)
	if length > size {
		panic("pad: len of block must be smaller than or equal to the blocksize")
	}
	var dst []byte
	var padByte byte
	if length == size {
		dst = make([]byte, 2*size)
		padByte = byte(length)
	} else {
		dst = make([]byte, size)
		padByte = byte(size - length)
	}
	copy(dst, block)
	dst[len(dst)-1] = padByte
	return dst
}

func (p x923Padding) Unpad(block []byte, size int) ([]byte, error) {
	if size <= 0 || size > 255 {
		panic("pad: illegal blocksize - size must between 0 and 256")
	}
	length := len(block)
	if length != size {
		panic("pad: len of block must be equal to the blocksize")
	}
	unLen, err := verifyX923(block, length)
	if err != nil {
		return nil, err
	}
	dst := make([]byte, unLen)
	copy(dst, block[:unLen])
	return dst, nil
}

func verifyX923(block []byte, length int) (uint, error) {
	var err error = nil
	padLen := block[length-1]
	if padLen == 0 || int(padLen) > length {
		err = LengthError(padLen)
	}
	padStart := length - int(padLen)
	for i := padStart; i < length-1; i++ {
		if block[i] != 0 && err == nil {
			err = ByteError(block[i])
		}
	}
	return uint(padStart), err
}
