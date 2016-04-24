// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package blake2s

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
	// Test vectors from https://blake2.net/blake2s-test.txt
	testVector{
		// without explicit hash size (check if default is used)
		params: &Params{Key: decodeHex(nil, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
		msg:    hex.EncodeToString([]byte("")),
		hash:   "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49",
	},
	testVector{
		params: &Params{HashSize: 32,
			Key: decodeHex(nil, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
		msg:  "00",
		hash: "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1",
	},
	testVector{
		params: &Params{HashSize: 32,
			Key: decodeHex(nil, "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")},
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
	p = &Params{HashSize: 33}
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed - Cause: %s", err)
	}
	p = &Params{Key: make([]byte, 32)}
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed - Cause: %s", err)
	}
	p = &Params{Key: make([]byte, 32), Salt: make([]byte, 8)}
	if err := verifyParams(p); err != nil {
		t.Fatalf("Verification of valid parameters failed - Cause: %s", err)
	}

	p = &Params{Key: make([]byte, 33)}
	if err := verifyParams(p); err == nil {
		t.Fatalf("Verification of invalid parameters passed - Key length: %d", len(p.Key))
	}
	p = &Params{Salt: make([]byte, 9)}
	if err := verifyParams(p); err == nil {
		t.Fatalf("Verification of invalid parameters passed - Salt length: %d", len(p.Salt))
	}
}

func TestBlockSize(t *testing.T) {
	h, err := New(&Params{HashSize: Size})
	if err != nil {
		t.Fatalf("Could not create blake2s instance: %s", err)
	}
	if bs := h.BlockSize(); bs != BlockSize || bs != 64 {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, 64)
	}
}

func TestSize(t *testing.T) {
	h, err := New(&Params{HashSize: Size})
	if err != nil {
		t.Fatalf("Could not create blake2s instance: %s", err)
	}
	if s := h.Size(); s != Size || s != 32 {
		t.Fatalf("Size() returned: %d - but expected: %d", s, 32)
	}

	h, err = New(&Params{HashSize: 16})
	if err != nil {
		t.Fatalf("Could not create blake2s instance: %s", err)
	}
	if s := h.Size(); s != Size/2 || s != 16 {
		t.Fatalf("Size() returned: %d - but expected: %d", s, 16)
	}
}

func TestReset(t *testing.T) {
	h, err := New(&Params{HashSize: Size})
	if err != nil {
		t.Fatalf("Could not create blake2s instance: %s", err)
	}
	b, ok := h.(*blake2s)
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
		t.Fatalf("Failed to create instance of blake2s - Cause: %s", err)
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
		t.Fatalf("Failed to create blake2s instance: %s", err)
	}

	p.HashSize = 80 // invalid but verify should adjust this
	_, err = New(p)
	if err != nil {
		t.Fatalf("Failed to create blake2s instance: %s", err)
	}

	p.Key = make([]byte, Size)
	_, err = New(p)
	if err != nil {
		t.Fatalf("Failed to create blake2s instance: %s", err)
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
		t.Fatalf("Failed to create blake2s instance: %s", err)
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
	h, err := New(&Params{HashSize: Size})
	if err != nil {
		t.Fatalf("Failed to create blake2s instance: %s", err)
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

func TestSum160(t *testing.T) {
	h, err := New(&Params{HashSize: 20})
	if err != nil {
		t.Fatalf("Failed to create blake2s instance: %s", err)
	}

	h.Write(nil)
	sum1 := h.Sum(nil)
	sum2 := Sum160(nil)
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
	h.Reset()

	h.Write(make([]byte, 1))
	sum1 = h.Sum(nil)
	sum2 = Sum160(make([]byte, 1))
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
	h.Reset()

	h.Write(make([]byte, BlockSize+1))
	sum1 = h.Sum(nil)
	sum2 = Sum160(make([]byte, BlockSize+1))
	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

func TestSum256(t *testing.T) {
	h, err := New(&Params{HashSize: Size})
	if err != nil {
		t.Fatalf("Failed to create blake2s instance: %s", err)
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

// Tests the Sum(msg []byte, p *Params) function declared within
// this package.
func TestSumFunc(t *testing.T) {
	p := &Params{}
	h, err := New(p)
	if err != nil {
		t.Fatalf("Failed to create blake2s instance: %s", err)
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
		t.Fatalf("Failed to create blake2s instance: %s", err)
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

	p.Salt = make([]byte, 6)
	h, err = New(p)
	if err != nil {
		t.Fatalf("Failed to create blake2s instance: %s", err)
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
		b.Fatalf("Failed to create blake2s hash - Cause: %s", err)
	}
	buf := make([]byte, h.BlockSize())
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(buf)
	}
}

func BenchmarkSum160(b *testing.B) {
	buf := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum160(buf)
	}
}

func BenchmarkSum256(b *testing.B) {
	buf := make([]byte, BlockSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum256(buf)
	}
}
