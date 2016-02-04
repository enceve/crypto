package crypto

import "strconv"

type KeySizeError int

func (k KeySizeError) Error() string {
	return "invalid key size " + strconv.Itoa(int(k))
}

type NonceSizeError int

func (n NonceSizeError) Error() string {
	return "invalid nonce size " + strconv.Itoa(int(n))
}
