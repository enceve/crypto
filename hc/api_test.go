// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package hc

import "testing"

func TestNew128(t *testing.T) {
	_, err := New128(make([]byte, 16), make([]byte, 16))
	if err != nil {
		t.Fatalf("Failed to create instance of HC-128: %s", err)
	}
	_, err = New128(make([]byte, 8), make([]byte, 16))
	if err == nil {
		t.Fatalf("Key verification failed - invalid key accepted")
	}
	_, err = New128(make([]byte, 17), make([]byte, 16))
	if err == nil {
		t.Fatalf("Key verification failed - invalid key accepted")
	}
	_, err = New128(make([]byte, 16), make([]byte, 17))
	if err == nil {
		t.Fatalf("Key verification failed - invalid nonce accepted")
	}
	_, err = New128(make([]byte, 16), make([]byte, 13))
	if err == nil {
		t.Fatalf("Key verification failed - invalid nonce accepted")
	}
}

func TestNew256(t *testing.T) {
	_, err := New256(make([]byte, 32), make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create instance of HC-128: %s", err)
	}
	_, err = New256(make([]byte, 28), make([]byte, 32))
	if err == nil {
		t.Fatalf("Key verification failed - invalid key accepted")
	}
	_, err = New256(make([]byte, 33), make([]byte, 32))
	if err == nil {
		t.Fatalf("Key verification failed - invalid key accepted")
	}
	_, err = New256(make([]byte, 32), make([]byte, 33))
	if err == nil {
		t.Fatalf("Key verification failed - invalid nonce accepted")
	}
	_, err = New256(make([]byte, 32), make([]byte, 31))
	if err == nil {
		t.Fatalf("Key verification failed - invalid nonce accepted")
	}
}
