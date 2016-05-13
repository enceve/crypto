// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package cmac

import (
	"bytes"
	"crypto/aes"
	"crypto/des"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"github.com/EncEve/crypto/threefish"
)

// Tests Blocksize() declared in hash.Hash
func TestBlockSize(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create AES instance: %s", err)
	}
	h, err := New(c)
	if err != nil {
		t.Fatalf("Could not create CMac instance: %s", err)
	}
	if bs := h.BlockSize(); bs != c.BlockSize() {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, c.BlockSize())
	}
}

// Tests Size() declared in hash.Hash
func TestSize(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create AES instance: %s", err)
	}
	h, err := New(c)
	if err != nil {
		t.Fatalf("Could not create CMac instance: %s", err)
	}
	if bs := h.Size(); bs != c.BlockSize() {
		t.Fatalf("Size() returned: %d - but expected: %d", bs, c.BlockSize())
	}
}

// Tests Reset() declared in hash.Hash
func TestReset(t *testing.T) {
	cipher, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create AES instance: %s", err)
	}
	h, err := New(cipher)
	c, ok := h.(*macFunc)
	if !ok {
		t.Fatal("Impossible situation: New returns no CMac struct")
	}
	orig := *c // copy

	var randData [aes.BlockSize]byte
	if _, err := rand.Read(randData[:]); err != nil {
		t.Fatalf("Failed to read random bytes form crypto/rand: %s", err)
	}

	c.Write(randData[:])
	c.Reset()

	if !bytes.Equal(c.buf, orig.buf) {
		t.Fatalf("Reseted buf field: %d - but expected: %d", c.buf, orig.buf)
	}
	if !bytes.Equal(c.k0, orig.k0) {
		t.Fatalf("Reseted k0 field: %d - but expected: %d", c.k0, orig.k0)
	}
	if !bytes.Equal(c.k1, orig.k1) {
		t.Fatalf("Reseted k1 field: %d - but expected: %d", c.k1, orig.k1)
	}
	if c.off != orig.off {
		t.Fatalf("Reseted off field: %d - but expected: %d", c.off, orig.off)
	}
	if c.cipher != orig.cipher {
		t.Fatalf("Reseted cipher field: %v - but expected: %v", c.cipher, orig.cipher)
	}
}

// Tests Write(p []byte) declared in hash.Hash
func TestWrite(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create AES instance: %s", err)
	}
	h, err := New(c)
	if err != nil {
		t.Fatalf("Failed to create CMac instance: %s", err)
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

// Tests Sum(b []byte) declared in hash.Hash
func TestSum(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create AES instance: %s", err)
	}
	h, err := New(c)
	if err != nil {
		t.Fatalf("Failed to create CMac instance: %s", err)
	}

	var one = [1]byte{1}

	h.Sum(nil)
	h.Write(make([]byte, aes.BlockSize))
	h.Write(one[:])

	sum1 := h.Sum(nil)
	sum2, err := Sum(append(make([]byte, aes.BlockSize), one[:]...), c)
	if err != nil {
		t.Fatalf("Failed to create CMac sum: %s", err)
	}
	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

// Tests New(c cipher.Block) declared here (cmac)
func TestNew(t *testing.T) {
	// Test 64 bit block cipher
	c, err := des.NewCipher(make([]byte, 8))
	if err != nil {
		t.Fatalf("Could not create DES instance: %s", err)
	}
	_, err = New(c)
	if err != nil {
		t.Fatalf("Failed to create CMac instance: %s", err)
	}

	// Test 128 bit block cipher
	c, err = aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create AES instance: %s", err)
	}
	_, err = New(c)
	if err != nil {
		t.Fatalf("Failed to create CMac instance: %s", err)
	}

	// Test 256 bit block cipher
	c, err = threefish.New256(make([]byte, 32), make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create Threefish-256 instance: %s", err)
	}
	_, err = New(c)
	if err != nil {
		t.Fatalf("Failed to create CMac instance: %s", err)
	}

	// Test 512 bit block cipher
	c, err = threefish.New512(make([]byte, 64), make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create Threefish-512 instance: %s", err)
	}
	_, err = New(c)
	if err != nil {
		t.Fatalf("Failed to create CMac instance: %s", err)
	}

	// Test 1024 bit block cipher
	c, err = threefish.New1024(make([]byte, 128), make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create Threefish-1024 instance: %s", err)
	}
	_, err = New(c)
	if err != nil {
		t.Fatalf("Failed to create CMac instance: %s", err)
	}
}

// Tests Sum(msg []byte, c cipher.Block) declared here (cmac)
func TestSumFunc(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create AES instance: %s", err)
	}
	h, err := New(c)
	if err != nil {
		t.Fatalf("Failed to create CMac instance: %s", err)
	}

	h.Write(nil)
	sum1 := h.Sum(nil)
	sum2, err := Sum(nil, c)
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}

	h.Reset()
	h.Write(make([]byte, 1))
	sum1 = h.Sum(nil)
	sum2, err = Sum(make([]byte, 1), c)
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !bytes.Equal(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

// Tests Sum(mac, msg []byte, c cipher.Block) declared here (cmac)
func TestVerify(t *testing.T) {
	c, err := aes.NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Could not create AES instance: %s", err)
	}

	msg := make([]byte, 211)
	sum, err := Sum(msg, c)
	if err != nil {
		t.Fatalf("Failed to calculate the sum: %s", err)
	}
	if !Verify(sum, msg, c) {
		t.Fatal("Verification failed")
	}
}
