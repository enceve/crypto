package blake2b

import (
	"encoding/hex"
	"testing"
)

func decodeHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		if t == nil {
			panic(err)
		}
		t.Fatalf("Failed to decode hex: %s\nCaused by: %s", s, err)
	}
	return b
}

type testVector struct {
	params    *Params
	msg, hash string
}

var vectors []testVector = []testVector{
	// Test vector https://tools.ietf.org/html/rfc7693#appendix-A
	testVector{
		params: &Params{}, // without explicit hash size (check if default is used)
		msg:    hex.EncodeToString([]byte("abc")),
		hash: "BA80A53F981C4D0D6A2797B69F12F6E94C212F14685AC4B74B12BB6FDBFFA2D1" +
			"7D87C5392AAB792DC252D5DE4533CC9518D38AA8DBF1925AB92386EDD4009923",
	},

	// Test vectors from https://en.wikipedia.org/wiki/BLAKE_%28hash_function%29#BLAKE2_hashes
	testVector{
		params: &Params{HashSize: 64},
		msg:    hex.EncodeToString([]byte("")),
		hash: "786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419" +
			"D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE",
	},
	testVector{
		params: &Params{HashSize: 64},
		msg:    hex.EncodeToString([]byte("The quick brown fox jumps over the lazy dog")),
		hash: "A8ADD4BDDDFD93E4877D2746E62817B116364A1FA7BC148D95090BC7333B3673" +
			"F82401CF7AA2E4CB1ECD90296E3F14CB5413F8ED77BE73045B13914CDCD6A918",
	},

	// Test vectors from https://blake2.net/blake2b-test.txt
	testVector{
		params: &Params{HashSize: 64,
			Key: decodeHex(nil, "000102030405060708090a0b0c0d0e0f10111213141"+
				"5161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233343"+
				"5363738393a3b3c3d3e3f")},
		msg: hex.EncodeToString([]byte("")),
		hash: "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786" +
			"b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568",
	},
	testVector{
		params: &Params{HashSize: 64,
			Key: decodeHex(nil, "000102030405060708090a0b0c0d0e0f1011121314151617181"+
				"91a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a"+
				"3b3c3d3e3f")},
		msg: "00",
		hash: "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4" +
			"187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd",
	},
	testVector{
		params: &Params{HashSize: 64,
			Key: decodeHex(nil, "000102030405060708090a0b0c0d0e0f10111213141516171819"+
				"1a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b"+
				"3c3d3e3f")},
		msg: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
			"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f4" +
			"04142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60" +
			"6162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808" +
			"182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1" +
			"a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c" +
			"2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2" +
			"e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfd",
		hash: "d444bfa2362a96df213d070e33fa841f51334e4e76866b8139e8af3bb3398be2" +
			"dfaddcbc56b9146de9f68118dc5829e74b0c28d7711907b121f9161cb92b69a9",
	},
}

func TestVectors(t *testing.T) {
	for i, v := range vectors {
		h, err := New(v.params)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to create new blake2b hash: %s", i, err)
		}
		msg := decodeHex(t, v.msg)
		expSum := decodeHex(t, v.hash)

		h.Write(msg)
		sum := h.Sum(nil)
		if len(sum) != len(expSum) {
			t.Fatalf("Test vector %d : Hash size does not match expected - found %d expected %d", i, len(sum), len(expSum))
		}
		for j := range sum {
			if sum[j] != expSum[j] {
				t.Fatalf("Test vector %d : Hash does not match:\nFound:    %s\nExpected: %s", i, hex.EncodeToString(sum), hex.EncodeToString(expSum))
			}
		}

		sum, err = Sum(msg, v.params)
		if err != nil {
			t.Fatalf("Test vector %d : funcion Sum failed - Cause: %s", i, err)
		}
		if len(sum) != len(expSum) {
			t.Fatalf("Test vector %d : Hash size does not match expected - found %d expected %d", i, len(sum), len(expSum))
		}
		for j := range sum {
			if sum[j] != expSum[j] {
				t.Fatalf("Test vector %d : Hash does not match:\nFound:    %s\nExpected: %s", i, hex.EncodeToString(sum), hex.EncodeToString(expSum))
			}
		}
	}
}
