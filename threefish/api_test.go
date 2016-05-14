// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package threefish

import (
	"bytes"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	buf, src := make([]byte, 32), make([]byte, 32)

	// 256 bit key
	c, err := NewCipher(make([]byte, 32), make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create Threefish-256 instance: %s", err)
	}
	c.Encrypt(buf, src)
	c.Decrypt(buf, buf)
	if !bytes.Equal(src, buf) {
		t.Fatalf("En/Decryption failed\nSrc:  %v\nBuf: %v", src, buf)
	}

	buf, src = make([]byte, 64), make([]byte, 64)

	// 512 bit key
	c, err = NewCipher(make([]byte, 64), make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create Threefish-512 instance: %s", err)
	}
	c.Encrypt(buf, src)
	c.Decrypt(buf, buf)
	if !bytes.Equal(src, buf) {
		t.Fatalf("En/Decryption failed\nSrc:  %v\nBuf: %v", src, buf)
	}

	buf, src = make([]byte, 128), make([]byte, 128)

	// 1024 bit key
	c, err = NewCipher(make([]byte, 128), make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create Threefish-1024 instance: %s", err)
	}
	c.Encrypt(buf, src)
	c.Decrypt(buf, buf)
	if !bytes.Equal(src, buf) {
		t.Fatalf("En/Decryption failed\nSrc:  %v\nBuf: %v", src, buf)
	}
}
