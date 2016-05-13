// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package camellia

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	buf, src := make([]byte, BlockSize), make([]byte, BlockSize)

	// 128 bit key
	c, err := NewCipher(make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create Camellia instance: %s", err)
	}
	c.Encrypt(buf, src)
	c.Decrypt(buf, buf)
	if !bytes.Equal(src, buf) {
		t.Fatalf("En/Decryption failed\nSrc:  %v\nBuf: %v", src, buf)
	}

	// 192 bit key
	c, err = NewCipher(make([]byte, 24))
	if err != nil {
		t.Fatalf("Failed to create Camellia instance: %s", err)
	}
	c.Encrypt(buf, src)
	c.Decrypt(buf, buf)
	if !bytes.Equal(src, buf) {
		t.Fatalf("En/Decryption failed\nSrc:  %v\nBuf: %v", src, buf)
	}

	// 256 bit key
	c, err = NewCipher(make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create Camellia instance: %s", err)
	}
	c.Encrypt(buf, src)
	c.Decrypt(buf, buf)
	if !bytes.Equal(src, buf) {
		t.Fatalf("En/Decryption failed\nSrc:  %v\nBuf: %v", src, buf)
	}
}
