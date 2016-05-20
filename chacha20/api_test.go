// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package chacha20

import "testing"

func TestNew(t *testing.T) {
	_, err := NewCipher(make([]byte, 32), make([]byte, 12))
	if err != nil {
		t.Fatalf("Failed to create instance of ChaCha20: %s", err)
	}
	_, err = NewCipher(make([]byte, 36), make([]byte, 12))
	if err == nil {
		t.Fatalf("Key verification failed - invalid key accepted")
	}
	_, err = NewCipher(make([]byte, 16), make([]byte, 12))
	if err == nil {
		t.Fatalf("Key verification failed - invalid key accepted")
	}
	_, err = NewCipher(make([]byte, 32), make([]byte, 11))
	if err == nil {
		t.Fatalf("Key verification failed - invalid nonce accepted")
	}
	_, err = NewCipher(make([]byte, 32), make([]byte, 32))
	if err == nil {
		t.Fatalf("Key verification failed - invalid nonce accepted")
	}
}

func TestNewAEAD(t *testing.T) {
	_, err := NewAEAD(make([]byte, 32), TagSize)
	if err != nil {
		t.Fatalf("Failed to create instance of ChaCha20: %s", err)
	}
	_, err = NewAEAD(make([]byte, 32), 12)
	if err != nil {
		t.Fatalf("Failed to create instance of ChaCha20: %s", err)
	}
	_, err = NewAEAD(make([]byte, 32), 8)
	if err != nil {
		t.Fatalf("Failed to create instance of ChaCha20: %s", err)
	}
	_, err = NewAEAD(make([]byte, 16), 12)
	if err == nil {
		t.Fatalf("Key verification failed - invalid key accepted")
	}
	_, err = NewAEAD(make([]byte, 36), TagSize)
	if err == nil {
		t.Fatalf("Key verification failed - invalid key accepted")
	}
	_, err = NewAEAD(make([]byte, 32), 17)
	if err == nil {
		t.Fatalf("TagSize verification failed - invalid tag size accepted")
	}
	_, err = NewAEAD(make([]byte, 32), 0)
	if err == nil {
		t.Fatalf("TagSize verification failed - invalid tag size accepted")
	}
}
