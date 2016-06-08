// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package chacha20

import "testing"

func TestNewAEAD(t *testing.T) {
	var key [32]byte
	_, err := NewAEAD(&key, TagSize)
	if err != nil {
		t.Fatalf("Failed to create ChaCha20Poly1305 instance: %s", err)
	}
	_, err = NewAEAD(&key, 12)
	if err != nil {
		t.Fatalf("Failed to create ChaCha20Poly1305 instance: %s", err)
	}
	_, err = NewAEAD(&key, 8)
	if err != nil {
		t.Fatalf("Failed to create ChaCha20Poly1305 instance: %s", err)
	}
	_, err = NewAEAD(&key, 17)
	if err == nil {
		t.Fatalf("TagSize verification failed - invalid tag size accepted")
	}
	_, err = NewAEAD(&key, 0)
	if err == nil {
		t.Fatalf("TagSize verification failed - invalid tag size accepted")
	}
}

func TestOverhead(t *testing.T) {
	var key [32]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		t.Fatalf("Failed to create ChaCha20Poly1305 instance: %s", err)
	}
	if o := c.Overhead(); o != TagSize {
		t.Fatalf("Max. overhead of ChaCha20Poly1305 is %d but Overhead() returned %d", TagSize, o)
	}
	c, err = NewAEAD(&key, 12)
	if err != nil {
		t.Fatalf("Failed to create ChaCha20Poly1305 instance: %s", err)
	}
	if o := c.Overhead(); o != 12 {
		t.Fatalf("Max. overhead of ChaCha20Poly1305 is %d but Overhead() returned %d", 12, o)
	}
}

func TestNonceSize(t *testing.T) {
	var key [32]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		t.Fatalf("Failed to create ChaCha20Poly1305 instance: %s", err)
	}
	if n := c.NonceSize(); n != NonceSize {
		t.Fatalf("The nonce size of ChaCha20Poly1305 is %d but NonceSize() returned %d", TagSize, n)
	}
}

func TestSeal(t *testing.T) {
	var key [32]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		t.Fatalf("Failed to create ChaCha20Poly1305 instance: %s", err)
	}
	var (
		nonce [NonceSize]byte
		src   [64]byte
		dst   [64 + TagSize]byte
	)
	recFunc := func(msg string) {
		if recover() == nil {
			t.Fatal(msg)
		}
	}
	func() {
		defer recFunc("Seal() accepted invalid nonce size")
		c.Seal(dst[:], nonce[:NonceSize-1], src[:], nil)
	}()
	func() {
		defer recFunc("Seal() accepted invalid dst length")
		c.Seal(dst[:len(dst)-2], nonce[:], src[:], nil)
	}()
}

func TestOpen(t *testing.T) {
	var key [32]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		t.Fatalf("Failed to create ChaCha20Poly1305 instance: %s", err)
	}
	var (
		nonce [NonceSize]byte
		src   [64]byte
		dst   [64 + TagSize]byte
	)
	_, err = c.Open(dst[:], nonce[:NonceSize-1], src[:], nil)
	if err == nil {
		t.Fatal("Open() accepted invalid nonce size")
	}
	_, err = c.Open(dst[:], nonce[:], src[:TagSize-1], nil)
	if err == nil {
		t.Fatal("Open() accepted invalid ciphertext length")
	}

	recFunc := func(msg string) {
		if recover() == nil {
			t.Fatal(msg)
		}
	}
	func() {
		defer recFunc("Open() accepted invalid dst length")
		c.Seal(dst[:len(src)-TagSize-1], nonce[:], src[:], nil)
	}()
}

func BenchmarkSeal64B(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 64)
	dst := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = c.Seal(dst, nonce[:], msg, data)
	}
}

func BenchmarkSeal256B(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 256)
	dst := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	b.SetBytes(256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = c.Seal(dst, nonce[:], msg, data)
	}
}

func BenchmarkSeal512B(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 512)
	dst := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	b.SetBytes(512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = c.Seal(dst, nonce[:], msg, data)
	}
}

func BenchmarkSeal1K(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 1024)
	dst := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = c.Seal(dst, nonce[:], msg, data)
	}
}

func BenchmarkSeal16K(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 16*1024)
	dst := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	b.SetBytes(16 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = c.Seal(dst, nonce[:], msg, data)
	}
}

func BenchmarkSeal64K(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 64*1024)
	dst := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	b.SetBytes(64 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst = c.Seal(dst, nonce[:], msg, data)
	}
}

func BenchmarkOpen64B(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 64)
	dst := make([]byte, len(msg))
	ciphertext := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	ciphertext = c.Seal(ciphertext, nonce[:], msg, data)
	b.SetBytes(64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = c.Open(dst, nonce[:], ciphertext, data)
	}
}

func BenchmarkOpen256B(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 256)
	dst := make([]byte, len(msg))
	ciphertext := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	ciphertext = c.Seal(ciphertext, nonce[:], msg, data)
	b.SetBytes(256)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = c.Open(dst, nonce[:], ciphertext, data)
	}
}

func BenchmarkOpen512B(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 512)
	dst := make([]byte, len(msg))
	ciphertext := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	ciphertext = c.Seal(ciphertext, nonce[:], msg, data)
	b.SetBytes(512)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = c.Open(dst, nonce[:], ciphertext, data)
	}
}

func BenchmarkOpen1K(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 1024)
	dst := make([]byte, len(msg))
	ciphertext := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	ciphertext = c.Seal(ciphertext, nonce[:], msg, data)
	b.SetBytes(1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = c.Open(dst, nonce[:], ciphertext, data)
	}
}

func BenchmarkOpen16K(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 16*1024)
	dst := make([]byte, len(msg))
	ciphertext := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	ciphertext = c.Seal(ciphertext, nonce[:], msg, data)
	b.SetBytes(16 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = c.Open(dst, nonce[:], ciphertext, data)
	}
}

func BenchmarkOpen64K(b *testing.B) {
	var key [32]byte
	var nonce [12]byte
	c, err := NewAEAD(&key, TagSize)
	if err != nil {
		b.Fatalf("Failed to create ChaCha-Poly1305 instance: %s", err)
	}
	msg := make([]byte, 64*1024)
	dst := make([]byte, len(msg))
	ciphertext := make([]byte, len(msg)+TagSize)
	data := make([]byte, 32)
	ciphertext = c.Seal(ciphertext, nonce[:], msg, data)
	b.SetBytes(64 * 1024)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dst, _ = c.Open(dst, nonce[:], ciphertext, data)
	}
}
