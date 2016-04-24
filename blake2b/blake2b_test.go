// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package blake2b

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

type testVector struct {
	params    *Params
	msg, hash string
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if b[i] != v {
			return false
		}
	}
	return true
}

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
			t.Fatalf("Test vector %d : Failed to create new blake2s hash - Caused by: %s", i, err)
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

func TestVerifyParams(t *testing.T) {
	p := new(Params)
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed - Cause: %s", err)
	}
	p = &Params{HashSize: 65}
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed - Cause: %s", err)
	}
	p = &Params{Key: make([]byte, 64)}
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed - Cause: %s", err)
	}
	p = &Params{Key: make([]byte, 64), Salt: make([]byte, 16)}
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed - Cause: %s", err)
	}

	p = &Params{Key: make([]byte, 65)}
	if err := verifyParams(p); err == nil {
		t.Fatalf("Verification of invalid parameters passed - Key length: %d", len(p.Key))
	}
	p = &Params{Salt: make([]byte, 17)}
	if err := verifyParams(p); err == nil {
		t.Fatalf("Verification of invalid parameters passed - Salt length: %d", len(p.Salt))
	}
}

func TestBlockSize(t *testing.T) {
	h, err := New(&Params{HashSize: Size})
	if err != nil {
		t.Fatalf("Could not create blake2b instance: %s", err)
	}
	if bs := h.BlockSize(); bs != BlockSize || bs != 128 {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, 128)
	}
}

func TestSize(t *testing.T) {
	h, err := New(&Params{HashSize: Size})
	if err != nil {
		t.Fatalf("Could not create blake2b instance: %s", err)
	}
	if s := h.Size(); s != Size || s != 64 {
		t.Fatalf("Size() returned: %d - but expected: %d", s, 64)
	}

	h, err = New(&Params{HashSize: 32})
	if err != nil {
		t.Fatalf("Could not create blake2b instance: %s", err)
	}
	if s := h.Size(); s != Size/2 || s != 32 {
		t.Fatalf("Size() returned: %d - but expected: %d", s, 32)
	}
}

func TestReset(t *testing.T) {
	h, err := New(&Params{HashSize: Size})
	if err != nil {
		t.Fatalf("Could not create blake2b instance: %s", err)
	}
	b, ok := h.(*blake2b)
	if !ok {
		t.Fatal("Impossible situation: New returns no blake2b struct")
	}
	orig := *b // copy

	var randData [BlockSize]byte
	if _, err := rand.Read(randData[:]); err != nil {
		t.Fatalf("Failed to read random bytes form crypto/rand: %s", err)
	}

	b.Write(randData[:])
	b.Reset()

	if b.hsize != orig.hsize {
		t.Fatalf("Reseted hsize field: %d - but expected: %d", b.hsize, orig.hsize)
	}
	if b.keyed != orig.keyed {
		t.Fatalf("Reseted keyed field: %v - but expected: %v", b.keyed, orig.keyed)
	}
	if b.ctr != orig.ctr {
		t.Fatalf("Reseted ctr field: %v - but expected: %v", b.ctr, orig.ctr)
	}
	if b.off != orig.off {
		t.Fatalf("Reseted off field: %d - but expected: %d", b.off, orig.off)
	}
	if b.buf != orig.buf {
		t.Fatalf("Reseted buf field %v - but expected %v", b.buf, orig.buf)
	}
	if b.key != orig.key {
		t.Fatalf("Reseted key field: %v - but expected: %v", b.key, orig.key)
	}
	if b.hVal != orig.hVal {
		t.Fatalf("Reseted hVal field: %v - but expected: %v", b.hVal, orig.hVal)
	}
	if b.initVal != orig.initVal {
		t.Fatalf("Reseted initVal field: %v - but expected: %v", b.initVal, orig.initVal)
	}
}

func TestWrite(t *testing.T) {
	h, err := New(&Params{})
	if err != nil {
		t.Fatalf("Failed to create instance of blake2b - Cause: %s", err)
	}
	n, err := h.Write(nil)
	if n != 0 || err != nil {
		t.Fatalf("Failed to process nil slice: Processed bytes: %d - Returned error: %s", n, err)
	}
	n, err = h.Write(make([]byte, h.Size()))
	if n != h.Size() || err != nil {
		t.Fatalf("Failed to process 0-slice with length %d: Processed bytes: %d - Returned error: %s", h.Size(), n, err)
	}
	n, err = h.Write(make([]byte, h.BlockSize()))
	if n != h.BlockSize() || err != nil {
		t.Fatalf("Failed to process 0-slice with length %d: Processed bytes: %d - Returned error: %s", h.BlockSize(), n, err)
	}
	n, err = h.Write(make([]byte, 211)) // 211 = (2*3*5*7)+1 is prime
	if n != 211 || err != nil {
		t.Fatalf("Failed to process 0-slice with length %d: Processed bytes: %d - Returned error: %s", 211, n, err)
	}
}

func TestNew(t *testing.T) {
	p := &Params{}
	_, err := New(p)
	if err != nil {
		t.Fatalf("Failed to create blake2b instance: %s", err)
	}

	p.HashSize = 80 // invalid but verify should adjust this
	_, err = New(p)
	if err != nil {
		t.Fatalf("Failed to create blake2b instance: %s", err)
	}

	p.Key = make([]byte, Size)
	_, err = New(p)
	if err != nil {
		t.Fatalf("Failed to create blake2b instance: %s", err)
	}

	p.Key = make([]byte, Size+1)
	_, err = New(p)
	if err == nil {
		t.Fatalf("Verification of key parameter failed: Accepted illegal keysize: %d", Size+1)
	}
	p.Key = nil

	p.Salt = make([]byte, saltSize)
	_, err = New(p)
	if err != nil {
		t.Fatalf("Failed to create blake2b instance: %s", err)
	}

	p.Salt = make([]byte, saltSize+1)
	_, err = New(p)
	if err == nil {
		t.Fatalf("Verification of salt parameter failed: Accepted illegal saltsize: %d", saltSize+1)
	}
	p.Salt = nil
}

// Tests the Sum(b []byte) function declared within
// the hash.Hash interface.
func TestSum(t *testing.T) {
	h, err := New(&Params{HashSize: 32})
	if err != nil {
		t.Fatalf("Failed to create blake2b instance: %s", err)
	}
	var one = [1]byte{1}

	h.Sum(nil)
	h.Write(make([]byte, BlockSize))
	h.Write(one[:])

	sum1 := h.Sum(nil)
	sum2 := Sum256(append(make([]byte, BlockSize), one[:]...))

	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

func TestSum256(t *testing.T) {
	h, err := New(&Params{HashSize: 32})
	if err != nil {
		t.Fatalf("Failed to create blake2b instance: %s", err)
	}

	h.Write(nil)
	sum1 := h.Sum(nil)
	sum2 := Sum256(nil)
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
	h.Reset()

	h.Write(make([]byte, 1))
	sum1 = h.Sum(nil)
	sum2 = Sum256(make([]byte, 1))
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
	h.Reset()

	h.Write(make([]byte, BlockSize+1))
	sum1 = h.Sum(nil)
	sum2 = Sum256(make([]byte, BlockSize+1))
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

func TestSum512(t *testing.T) {
	h, err := New(&Params{HashSize: Size})
	if err != nil {
		t.Fatalf("Failed to create blake2b instance: %s", err)
	}

	h.Write(nil)
	sum1 := h.Sum(nil)
	sum2 := Sum512(nil)
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
	h.Reset()

	h.Write(make([]byte, 1))
	sum1 = h.Sum(nil)
	sum2 = Sum512(make([]byte, 1))
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
	h.Reset()

	h.Write(make([]byte, BlockSize+1))
	sum1 = h.Sum(nil)
	sum2 = Sum512(make([]byte, BlockSize+1))
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

// Tests the Sum(msg []byte, p *Params) function declared within
// this package.
func TestSumFunc(t *testing.T) {
	p := &Params{}
	h, err := New(p)
	if err != nil {
		t.Fatalf("Failed to create blake2b instance: %s", err)
	}

	h.Write(nil)
	sum1 := h.Sum(nil)
	sum2, err := Sum(nil, p)
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}

	p.HashSize = 48
	h, err = New(p)
	if err != nil {
		t.Fatalf("Failed to create blake2b instance: %s", err)
	}

	h.Write(make([]byte, 1))
	sum1 = h.Sum(nil)
	sum2, err = Sum(make([]byte, 1), p)
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}

	p.Salt = make([]byte, 14)
	h, err = New(p)
	if err != nil {
		t.Fatalf("Failed to create blake2b instance: %s", err)
	}

	h.Write(make([]byte, BlockSize+1))
	sum1 = h.Sum(nil)
	sum2, err = Sum(make([]byte, BlockSize+1), p)
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

func BenchmarkWrite(b *testing.B) {
	h, err := New(&Params{})
	if err != nil {
		b.Fatalf("Failed to create blake2b hash - Cause: %s", err)
	}
	buf := make([]byte, h.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkSum256(b *testing.B) {
	buf := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum256(buf)
	}
}

func BenchmarkSum512(b *testing.B) {
	buf := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum512(buf)
	}
}
