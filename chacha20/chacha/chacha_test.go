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

func TestCipherXORKeyStream(t *testing.T) {
	var key [32]byte
	var nonce [12]byte

	bufPart1 := make([]byte, 100)
	bufPart1[50] = 0x50
	bufPart2 := make([]byte, 100)
	bufPart1[42] = 0x42

	dst0 := make([]byte, len(bufPart1)+len(bufPart2))
	dst1 := make([]byte, len(dst0))

	c := NewCipher(&nonce, &key, 20)
	c.XORKeyStream(dst0, bufPart1)
	c.XORKeyStream(dst0[len(bufPart1):], bufPart2)

	XORKeyStream(dst1, append(bufPart1, bufPart2...), &nonce, &key, 0, 20)

	if !bytes.Equal(dst0, dst1) {
		t.Fatalf("\nc.XORKeyStream: %s\nXORKeyStream:   %s", hex.EncodeToString(dst0), hex.EncodeToString(dst1))
	}
}
