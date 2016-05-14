// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package serpent

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	dst, src := make([]byte, BlockSize), make([]byte, BlockSize)
	dstCp, srcCp := make([]byte, BlockSize), make([]byte, BlockSize)

	_, err := rand.Read(src)
	if err != nil {
		t.Fatalf("Failed to read from random source: %s", err)
	}
	copy(srcCp, src)
	_, err = rand.Read(dst)
	if err != nil {
		t.Fatalf("Failed to read from random source: %s", err)
	}
	copy(dstCp, dst)

	// 128 bit key
	key := make([]byte, 16)
	_, err = rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to read from random source: %s", err)
	}
	c, err := NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create Serpent instance: %s", err)
	}
	c.Encrypt(dst, src)
	c.Decrypt(src, dst)
	if !bytes.Equal(src, srcCp) {
		t.Fatalf("En/Decryption of dst to src failed\nKey: %v\nSrc:  %v\nDst: %v", key, srcCp, dst)
	}

	// 192 bit key
	key = make([]byte, 24)
	_, err = rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to read from random source: %s", err)
	}
	c, err = NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create Serpent instance: %s", err)
	}
	c.Encrypt(dst, src)
	c.Decrypt(src, dst)
	if !bytes.Equal(src, srcCp) {
		t.Fatalf("En/Decryption of dst to src failed\nKey: %v\nSrc:  %v\nDst: %v", key, srcCp, dst)
	}

	// 256 bit key
	key = make([]byte, 32)
	_, err = rand.Read(key)
	if err != nil {
		t.Fatalf("Failed to read from random source: %s", err)
	}
	c, err = NewCipher(key)
	if err != nil {
		t.Fatalf("Failed to create Serpent instance: %s", err)
	}
	c.Encrypt(dst, src)
	c.Decrypt(src, dst)
	if !bytes.Equal(src, srcCp) {
		t.Fatalf("En/Decryption of dst to src failed\nKey: %v\nSrc:  %v\nDst: %v", key, srcCp, dst)
	}
}
