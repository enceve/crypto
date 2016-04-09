// This code is taken from the golang poly1305 implementation.
// https://godoc.org/golang.org/x/crypto/poly1305

// +build arm,!gccgo,!appengine

package poly1305

// This function is implemented in poly1305_arm.s

//go:noescape
func poly1305_auth_armv6(out *[16]byte, m *byte, mlen uint32, key *[32]byte)

// Sum generates an authenticator for msg using a one-time key and puts the
// 16-byte result into out. Authenticating two different messages with the same
// key allows an attacker to forge messages at will.
func Sum(out *[16]byte, msg []byte, key *[32]byte) {
	var mPtr *byte
	if len(msg) > 0 {
		mPtr = &msg[0]
	}
	poly1305_auth_armv6(out, mPtr, uint32(len(msg)), key)
}
