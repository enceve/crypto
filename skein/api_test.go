// Use of this source code is governed by a license
// that can be found in the LICENSE file

package skein

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"
)

// Tests Blocksize() declared in hash.Hash
func TestBlockSize(t *testing.T) {
	h, err := New(&Params{BlockSize: Size256})
	if err != nil {
		t.Fatalf("Could not create Skein-256 instance: %s", err)
	}
	if bs := h.BlockSize(); bs != Size256 || bs != 32 {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, 32)
	}

	h, err = New(&Params{BlockSize: Size512})
	if err != nil {
		t.Fatalf("Could not create Skein-512 instance: %s", err)
	}
	if bs := h.BlockSize(); bs != Size512 || bs != 64 {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, 64)
	}

	h, err = New(&Params{BlockSize: Size1024})
	if err != nil {
		t.Fatalf("Could not create Skein-1024 instance: %s", err)
	}
	if bs := h.BlockSize(); bs != Size1024 || bs != 128 {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, 128)
	}
}

// Tests Size() declared in hash.Hash
func TestSize(t *testing.T) {
	h, err := New(&Params{BlockSize: Size256, HashSize: 20})
	if err != nil {
		t.Fatalf("Could not create Skein-256 instance: %s", err)
	}
	if s := h.Size(); s != 20 {
		t.Fatalf("Size() returned: %d - but expected: %d", s, 20)
	}

	h, err = New(&Params{BlockSize: Size512, HashSize: Size512})
	if err != nil {
		t.Fatalf("Could not create Skein-512 instance: %s", err)
	}
	if s := h.Size(); s != Size512 || s != 64 {
		t.Fatalf("Size() returned: %d - but expected: %d", s, 64)
	}

	h, err = New(&Params{BlockSize: Size1024, HashSize: Size1024})
	if err != nil {
		t.Fatalf("Could not create Skein-1024 instance: %s", err)
	}
	if s := h.Size(); s != Size1024 || s != 128 {
		t.Fatalf("Size() returned: %d - but expected: %d", s, 128)
	}
}

// Tests Reset() declared in hash.Hash for skein256
func TestReset256(t *testing.T) {
	h, err := New(&Params{BlockSize: Size256})
	if err != nil {
		t.Fatalf("Could not create Skein-256 instance: %s", err)
	}
	s, ok := h.(*skein256)
	if !ok {
		t.Fatal("Impossible situation: New returns no skein256 struct")
	}
	orig := *s // copy

	var randData [Size256]byte
	if _, err := rand.Read(randData[:]); err != nil {
		t.Fatalf("Failed to read random bytes form crypto/rand: %s", err)
	}

	s.Write(randData[:])
	s.Reset()

	if s.hsize != orig.hsize {
		t.Fatalf("Reseted hsize field: %d - but expected: %d", s.hsize, orig.hsize)
	}
	if s.msg != orig.msg {
		t.Fatalf("Reseted msg field: %v - but expected: %v", s.msg, orig.msg)
	}
	if s.off != orig.off {
		t.Fatalf("Reseted off field: %d - but expected: %d", s.off, orig.off)
	}
	if s.buf != orig.buf {
		t.Fatalf("Reseted buf field %v - but expected %v", s.buf, orig.buf)
	}
	if s.tweak != orig.tweak {
		t.Fatalf("Reseted tweak field: %v - but expected: %v", s.tweak, orig.tweak)
	}
	if s.hVal != orig.hVal {
		t.Fatalf("Reseted hVal field: %v - but expected: %v", s.hVal, orig.hVal)
	}
	if s.initVal != orig.initVal {
		t.Fatalf("Reseted initVal field: %v - but expected: %v", s.initVal, orig.initVal)
	}
}

// Tests Reset() declared in hash.Hash for skein512
func TestReset512(t *testing.T) {
	h, err := New(&Params{BlockSize: Size512})
	if err != nil {
		t.Fatalf("Could not create Skein-512 instance: %s", err)
	}
	s, ok := h.(*skein512)
	if !ok {
		t.Fatal("Impossible situation: New returns no skein512 struct")
	}
	orig := *s // copy

	var randData [Size512]byte
	if _, err := rand.Read(randData[:]); err != nil {
		t.Fatalf("Failed to read random bytes form crypto/rand: %s", err)
	}

	s.Write(randData[:])
	s.Reset()

	if s.hsize != orig.hsize {
		t.Fatalf("Reseted hsize field: %d - but expected: %d", s.hsize, orig.hsize)
	}
	if s.msg != orig.msg {
		t.Fatalf("Reseted msg field: %v - but expected: %v", s.msg, orig.msg)
	}
	if s.off != orig.off {
		t.Fatalf("Reseted off field: %d - but expected: %d", s.off, orig.off)
	}
	if s.buf != orig.buf {
		t.Fatalf("Reseted buf field %v - but expected %v", s.buf, orig.buf)
	}
	if s.tweak != orig.tweak {
		t.Fatalf("Reseted tweak field: %v - but expected: %v", s.tweak, orig.tweak)
	}
	if s.hVal != orig.hVal {
		t.Fatalf("Reseted hVal field: %v - but expected: %v", s.hVal, orig.hVal)
	}
	if s.initVal != orig.initVal {
		t.Fatalf("Reseted initVal field: %v - but expected: %v", s.initVal, orig.initVal)
	}
}

// Tests Reset() declared in hash.Hash for skein1024
func TestReset1024(t *testing.T) {
	h, err := New(&Params{BlockSize: Size1024})
	if err != nil {
		t.Fatalf("Could not create Skein-1024 instance: %s", err)
	}
	s, ok := h.(*skein1024)
	if !ok {
		t.Fatal("Impossible situation: New returns no skein1024 struct")
	}
	orig := *s // copy

	var randData [Size1024]byte
	if _, err := rand.Read(randData[:]); err != nil {
		t.Fatalf("Failed to read random bytes form crypto/rand: %s", err)
	}

	s.Write(randData[:])
	s.Reset()

	if s.hsize != orig.hsize {
		t.Fatalf("Reseted hsize field: %d - but expected: %d", s.hsize, orig.hsize)
	}
	if s.msg != orig.msg {
		t.Fatalf("Reseted msg field: %v - but expected: %v", s.msg, orig.msg)
	}
	if s.off != orig.off {
		t.Fatalf("Reseted off field: %d - but expected: %d", s.off, orig.off)
	}
	if s.buf != orig.buf {
		t.Fatalf("Reseted buf field %v - but expected %v", s.buf, orig.buf)
	}
	if s.tweak != orig.tweak {
		t.Fatalf("Reseted tweak field: %v - but expected: %v", s.tweak, orig.tweak)
	}
	if s.hVal != orig.hVal {
		t.Fatalf("Reseted hVal field: %v - but expected: %v", s.hVal, orig.hVal)
	}
	if s.initVal != orig.initVal {
		t.Fatalf("Reseted initVal field: %v - but expected: %v", s.initVal, orig.initVal)
	}
}

// Tests Write(p []byte) declared in hash.Hash for skein256
func TestWrite256(t *testing.T) {
	h, err := New(&Params{BlockSize: Size256})
	if err != nil {
		t.Fatalf("Failed to create instance of Skein-256: %s", err)
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

// Tests Write(p []byte) declared in hash.Hash for skein512
func TestWrite512(t *testing.T) {
	h, err := New(&Params{BlockSize: Size512})
	if err != nil {
		t.Fatalf("Failed to create instance of Skein-512: %s", err)
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

// Tests Write(p []byte) declared in hash.Hash for skein1024
func TestWrite1024(t *testing.T) {
	h, err := New(&Params{BlockSize: Size1024})
	if err != nil {
		t.Fatalf("Failed to create instance of Skein-256: %s", err)
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

// Tests Sum(b []byte) declared in hash.Hash for skein256
func TestSum256(t *testing.T) {
	h, err := New(&Params{BlockSize: Size256})
	if err != nil {
		t.Fatalf("Failed to create Skein-256 instance: %s", err)
	}
	var one = [1]byte{1}

	h.Sum(nil)
	h.Write(make([]byte, Size256))
	h.Write(one[:])

	sum1 := h.Sum(nil)
	sum2, err := Sum(append(make([]byte, Size256), one[:]...), &Params{BlockSize: Size256})
	if err != nil {
		t.Fatalf("Failed to calculate check sum: %s", err)
	}

	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

// Tests Sum(b []byte) declared in hash.Hash for skein512
func TestSum512(t *testing.T) {
	h, err := New(&Params{BlockSize: Size512})
	if err != nil {
		t.Fatalf("Failed to create Skein-512 instance: %s", err)
	}
	var one = [1]byte{1}

	h.Sum(nil)
	h.Write(make([]byte, Size512))
	h.Write(one[:])

	sum1 := h.Sum(nil)
	sum2, err := Sum(append(make([]byte, Size512), one[:]...), &Params{BlockSize: Size512})
	if err != nil {
		t.Fatalf("Failed to calculate check sum: %s", err)
	}

	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

// Tests Sum(b []byte) declared in hash.Hash for skein1024
func TestSum1024(t *testing.T) {
	h, err := New(&Params{BlockSize: Size1024})
	if err != nil {
		t.Fatalf("Failed to create Skein-1024 instance: %s", err)
	}
	var one = [1]byte{1}

	h.Sum(nil)
	h.Write(make([]byte, Size1024))
	h.Write(one[:])

	sum1 := h.Sum(nil)
	sum2, err := Sum(append(make([]byte, Size1024), one[:]...), &Params{BlockSize: Size1024})
	if err != nil {
		t.Fatalf("Failed to calculate check sum: %s", err)
	}

	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

// Tests Sum(msg []byte. p *Params) declared here (skein)
func TestSumFunc(t *testing.T) {
	p := &Params{BlockSize: Size256}
	h, err := New(p)
	if err != nil {
		t.Fatalf("Failed to create skein instance: %s", err)
	}

	h.Write(nil)
	sum1 := h.Sum(nil)
	sum2, err := Sum(nil, p)
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !bytes.Equal(sum1, sum2) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}

	p = &Params{BlockSize: Size512}
	h, err = New(p)
	if err != nil {
		t.Fatalf("Failed to create Skein-512 instance: %s", err)
	}

	h.Write(make([]byte, 1))
	sum1 = h.Sum(nil)
	sum2, err = Sum(make([]byte, 1), p)
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !bytes.Equal(sum1, sum2) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}

	p = &Params{BlockSize: Size1024}
	h, err = New(p)
	if err != nil {
		t.Fatalf("Failed to create Skein-1024 instance: %s", err)
	}

	h.Write(make([]byte, 1))
	sum1 = h.Sum(nil)
	sum2, err = Sum(make([]byte, 1), p)
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !bytes.Equal(sum1, sum2) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}
