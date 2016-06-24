// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package chacha

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestXORBlocks128(t *testing.T) {
	var (
		state0 [16]uint32
		buf128 [128]byte

		state1 [16]uint32
		buf64  [64]byte
	)
	copy(state0[:4], constants[:])
	copy(state1[:4], constants[:])

	XORBlocks(buf128[:], buf128[:], &state0, 20)
	Core(&buf64, &state1, 20)
	state1[12]++

	if !bytes.Equal(buf128[:64], buf64[:]) {
		t.Fatalf("First 64 byte keystream don't match: \nXORBlocks: %s\nCore:      %s", hex.EncodeToString(buf128[:64]), hex.EncodeToString(buf64[:]))
	}

	Core(&buf64, &state1, 20)
	state1[12]++
	if !bytes.Equal(buf128[64:], buf64[:]) {
		t.Fatalf("Second 64 byte keystream don't match: \nXORBlocks: %s\nCore:      %s", hex.EncodeToString(buf128[64:]), hex.EncodeToString(buf64[:]))
	}
}

func TestXORBlocks256(t *testing.T) {
	var (
		state0 [16]uint32
		buf256 [256]byte

		state1 [16]uint32
		buf64  [64]byte
	)
	copy(state0[:4], constants[:])
	copy(state1[:4], constants[:])

	XORBlocks(buf256[:], buf256[:], &state0, 20)
	Core(&buf64, &state1, 20)
	state1[12]++

	if !bytes.Equal(buf256[:64], buf64[:]) {
		t.Fatalf("First 64 byte keystream don't match: \nXORBlocks: %s\nCore:      %s", hex.EncodeToString(buf256[:64]), hex.EncodeToString(buf64[:]))
	}

	Core(&buf64, &state1, 20)
	state1[12]++
	if !bytes.Equal(buf256[64:128], buf64[:]) {
		t.Fatalf("Second 64 byte keystream don't match: \nXORBlocks: %s\nCore:       %s", hex.EncodeToString(buf256[64:128]), hex.EncodeToString(buf64[:]))
	}

	Core(&buf64, &state1, 20)
	state1[12]++
	if !bytes.Equal(buf256[128:192], buf64[:]) {
		t.Fatalf("Third 64 byte keystream don't match: \nXORBlocks: %s\nCore:      %s", hex.EncodeToString(buf256[128:192]), hex.EncodeToString(buf64[:]))
	}

	Core(&buf64, &state1, 20)
	if !bytes.Equal(buf256[192:], buf64[:]) {
		t.Fatalf("Fourth 64 byte keystream don't match: \nXORBlocks: %s\nCore:      %s", hex.EncodeToString(buf256[192:]), hex.EncodeToString(buf64[:]))
	}
}
