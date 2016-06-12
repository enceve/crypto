// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package blake2s

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func fromHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var vectors = []struct {
	hashsize  int
	conf      *Config
	msg, hash string
}{
	// Test vectors from https://blake2.net/blake2s-test.txt
	{
		hashsize: 32,
		conf:     &Config{Key: fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
		msg:      hex.EncodeToString([]byte("")),
		hash:     "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
	},
	{
		hashsize: 32,
		conf:     &Config{Key: fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
		msg:      "00",
		hash:     "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1",
	},
	{
		hashsize: 32,
		conf:     &Config{Key: fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
		msg:      "000102030405060708090a",
		hash:     "e33c4c9bd0cc7e45c80e65c77fa5997fec7002738541509e68a9423891e822a3",
	},
	{
		hashsize: 32,
		conf:     &Config{Key: fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
		msg:      "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		hash:     "c03bc642b20959cbe133a0303e0c1abff3e31ec8e1a328ec8565c36decff5265",
	},
	{
		hashsize: 32,
		conf:     &Config{Key: fromHex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
		msg: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414" +
			"2434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f6061626364" +
			"65666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868" +
			"788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9" +
			"aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbc" +
			"ccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedee" +
			"eff0f1f2f3f4f5f6f7f8f9fafbfcfdfe",
		hash: "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd",
	},
}

func TestVectors(t *testing.T) {
	for i, v := range vectors {
		h, err := New(v.hashsize, v.conf)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to create new BLAKE2s instance: %s", i, err)
		}
		msg := fromHex(v.msg)
		expSum := fromHex(v.hash)

		h.Write(msg)
		sum := h.Sum(nil)
		if !bytes.Equal(sum, expSum) {
			t.Fatalf("Test vector %d : Hash does not match:\nFound:    %s\nExpected: %s", i, hex.EncodeToString(sum), hex.EncodeToString(expSum))
		}

		sum, err = Sum(msg, v.hashsize, v.conf)
		if err != nil {
			t.Fatalf("Test vector %d : function Sum failed: %s", i, err)
		}
		if !bytes.Equal(sum, expSum) {
			t.Fatalf("Test vector %d : Hash does not match:\nFound:    %s\nExpected: %s", i, hex.EncodeToString(sum), hex.EncodeToString(expSum))
		}
	}
}

func generateSequence(out []byte, seed uint32) {
	a := 0xDEAD4BAD * seed // prime
	b := uint32(1)

	for i := range out { // fill the buf
		t := a + b
		a = b
		b = t
		out[i] = byte(t >> 24)
	}
}

// BLAKE2s self-test validation from
// https://tools.ietf.org/html/rfc7693#appendix-E
func TestSelfTest(t *testing.T) {
	var result = [32]byte{
		0x6A, 0x41, 0x1F, 0x08, 0xCE, 0x25, 0xAD, 0xCD,
		0xFB, 0x02, 0xAB, 0xA6, 0x41, 0x45, 0x1C, 0xEC,
		0x53, 0xC5, 0x98, 0xB2, 0x4F, 0x4F, 0xC7, 0x87,
		0xFB, 0xDC, 0x88, 0x79, 0x7F, 0x4C, 0x1D, 0xFE,
	}
	var hashLens = [4]int{16, 20, 28, 32}
	var msgLens = [6]int{0, 3, 64, 65, 255, 1024}

	msg := make([]byte, 1024)
	key := make([]byte, 32)

	h, err := New(32, nil)
	if err != nil {
		t.Fatalf("Failed to create BLAKE2s instance: %s", err)
	}
	for _, hashsize := range hashLens {
		for _, msgLength := range msgLens {
			generateSequence(msg[:msgLength], uint32(msgLength)) // unkeyed hash
			md, err := Sum(msg[:msgLength], hashsize, nil)
			if err != nil {
				t.Fatalf("Selftest failed: Failed to compute unkeyed hash: %s", err)
			}
			h.Write(md)

			generateSequence(key[:], uint32(hashsize)) // keyed hash
			md, err = Sum(msg[:msgLength], hashsize, &Config{Key: key[:hashsize]})
			if err != nil {
				t.Fatalf("Selftest failed: Failed to compute keyed hash: %s", err)
			}
			h.Write(md)
		}
	}

	sum := h.Sum(nil)
	if !bytes.Equal(sum, result[:]) {
		t.Fatalf("Selftest failed:\nFound: %s\nExpected: %s", hex.EncodeToString(sum), hex.EncodeToString(result[:]))
	}
}
