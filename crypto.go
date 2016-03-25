// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The crypto package contains commen and general useful
// cryptographic functions and types.
package crypto

import "strconv"

// A KeySizeError indicates, that the size of a given key
// does not match the expected size.
type KeySizeError int

func (k KeySizeError) Error() string {
	return "invalid key size " + strconv.Itoa(int(k))
}

// A KeySizeError indicates, that the size of a given key
// does not match the expected size.
type NonceSizeError int

func (n NonceSizeError) Error() string {
	return "invalid nonce size " + strconv.Itoa(int(n))
}

// A AuthenticationError indicates, that an authentication
// process failed. E.g. the message authentication of a AEAD
// cipher.
type AuthenticationError struct{}

func (a AuthenticationError) Error() string {
	return "authentication failed"
}
