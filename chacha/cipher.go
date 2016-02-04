// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// The chacha package implements Bernstein's Chacha stream cipher algorithm.
// http://cr.yp.to/chacha/chacha-20080128.pdf
// There are two variants of this cipher: the original by Bernstein and one
// version described in RFC 7539 (https://tools.ietf.org/html/rfc7539).
// Both are implemented here.
package chacha

import (
	"errors"
	"github.com/enceve/crypto"
)

// The default number of rounds
// Another common value is 12
const DefaultRounds = 20

// The default start value for the counter part
const Zero = 0

// The constants for a 256 bit key
var sigma = []byte{'e', 'x', 'p', 'a', 'n', 'd', ' ', '3', '2', '-', 'b', 'y', 't', 'e', ' ', 'k'}

// The constants for a 128 bit key
var tau = []byte{'e', 'x', 'p', 'a', 'n', 'd', ' ', '1', '6', '-', 'b', 'y', 't', 'e', ' ', 'k'}

// Chacha describs an instance of the orig. chacha cipher.
type Chacha struct {
	state  [16]uint32
	stream [64]byte
	off    uint
	rounds uint
}

// ChachaRFC describs an instance of the RFC version of the chacha cipher.
type ChachaRFC struct {
	state  [16]uint32
	stream [64]byte
	off    uint
}

// Create a new chacha instance from the key (128 or 256 bit),
// the nonce (64 bit) and the number of rounds (common values are 20 or 12).
// The initial counter (64 bit) will be set to 0.
func New(key, nonce []byte, nRounds uint) (*Chacha, error) {
	if k := len(key); k != 16 && k != 32 {
		return nil, crypto.KeySizeError(k)
	}
	if n := len(nonce); n < 8 {
		return nil, crypto.NonceSizeError(n)
	}
	if nRounds%2 != 0 {
		return nil, errors.New("the number of rounds must be even")
	}
	c := &Chacha{
		off:    64,
		rounds: nRounds,
	}
	initialize(key, nonce, &(c.state))
	return c, nil
}

// Create a new chacha instance from the key (256 bit) and
// the nonce (96 bit). The number of rounds is fixed to 20.
// The initial counter (32 bit) will be set to 0.
func NewRFC(key, nonce []byte) (*ChachaRFC, error) {
	if k := len(key); k != 32 {
		return nil, crypto.KeySizeError(k)
	}
	if n := len(nonce); n < 12 {
		return nil, crypto.NonceSizeError(n)
	}
	c := &ChachaRFC{
		off: 64,
	}
	initializeRFC(key, nonce, &(c.state))
	return c, nil
}
