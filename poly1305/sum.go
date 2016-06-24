// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package poly1305

import poly "golang.org/x/crypto/poly1305"

// Sum generates an authenticator for msg using a one-time key and puts the
// 16-byte result into out. Authenticating two different messages with the same
// key allows an attacker to forge messages at will.
func Sum(out *[TagSize]byte, msg []byte, key *[32]byte) {
	poly.Sum(out, msg, key)
}
