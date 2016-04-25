// Use of this source code is governed by a license
// that can be found in the LICENSE file

package poly1305

import (
	"encoding/hex"
	"testing"
)

type testVector struct {
	key, msg, tag string
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

var vectors = []testVector{
	testVector{
		key: "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
		msg: "43727970746f6772617068696320466f72756d2052657365617263682047726f7570",
		tag: "a8061dc1305136c6c22b8baf0c0127a9",
	},
}

func TestVectors(t *testing.T) {
	for i, v := range vectors {
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to decode key - Cause: %s", i, err)
		}
		msg, err := hex.DecodeString(v.msg)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to decode msg - Cause: %s", i, err)
		}
		tag, err := hex.DecodeString(v.tag)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to decode tag - Cause: %s", i, err)
		}

		var sum [TagSize]byte
		var k [32]byte

		copy(k[:], key)
		Sum(&sum, msg, &k)
		for i, v := range tag {
			if sum[i] != v {
				t.Fatalf("Test vector %d : Poly1305 Tags are not equal:\nFound:    %v\nExpected: %v", i, sum, tag)
			}
		}

		p, err := New(key)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to create poly1305 instance - Cause: %s", i, err)
		}
		p.Write(msg)
		s := p.Sum(nil)
		for i, v := range tag {
			if s[i] != v {
				t.Fatalf("Test vector %d : Poly1305 Tags are not equal:\nFound:    %v\nExpected: %v", i, s, tag)
			}
		}
	}
}

func TestVerify(t *testing.T) {
	for i, v := range vectors {
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to decode key - Cause: %s", i, err)
		}
		msg, err := hex.DecodeString(v.msg)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to decode msg - Cause: %s", i, err)
		}
		tag, err := hex.DecodeString(v.tag)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to decode tag - Cause: %s", i, err)
		}

		var sum [TagSize]byte
		var k [32]byte

		copy(k[:], key)
		copy(sum[:], tag)

		if !Verify(&sum, msg, &k) {
			t.Fatalf("Test vector %d : Poly1305 Verification failed", i)
		}
	}
}

func TestBlockSize(t *testing.T) {
	h, err := New(make([]byte, 32))
	if err != nil {
		t.Fatalf("Could not create Poly1305 instance: %s", err)
	}
	if bs := h.BlockSize(); bs != TagSize || bs != 16 {
		t.Fatalf("BlockSize() returned: %d - but expected: %d", bs, 16)
	}
}

func TestSize(t *testing.T) {
	h, err := New(make([]byte, 32))
	if err != nil {
		t.Fatalf("Could not create Poly1305 instance: %s", err)
	}
	if s := h.Size(); s != TagSize || s != 16 {
		t.Fatalf("Size() returned: %d - but expected: %d", s, 16)
	}
}

func TestWrite(t *testing.T) {
	h, err := New(make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create instance of Poly1305 - Cause: %s", err)
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
	_, err := New(make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create Poly1305 instance: %s", err)
	}

	_, err = New(nil)
	if err == nil {
		t.Fatal("Accepted invalid nil argument for key")
	}

	_, err = New(make([]byte, TagSize))
	if err == nil {
		t.Fatalf("Accepted invalid key argument with len: %d", TagSize)
	}

	_, err = New(make([]byte, 33))
	if err == nil {
		t.Fatalf("Accepted invalid key argument with len: %d", 33)
	}
}

// Tests the Sum(b []byte) function declared within
// the hash.Hash interface.
func TestSum(t *testing.T) {
	h, err := New(make([]byte, 32))
	if err != nil {
		t.Fatalf("Failed to create Poly130 instance: %s", err)
	}
	var one = [1]byte{1}

	h.Sum(nil)
	h.Write(make([]byte, TagSize))
	h.Write(one[:])

	sum1 := h.Sum(nil)

	var key [32]byte
	var sum2 [16]byte
	Sum(&sum2, append(make([]byte, TagSize), one[:]...), &key)

	if !bytesEqual(sum1, sum2[:]) {
		t.Fatalf("Hash does not match:\nFound:    %s\nExpected: %s", hex.EncodeToString(sum1), hex.EncodeToString(sum2[:]))
	}
}

func BenchmarkWrite(b *testing.B) {
	h, err := New(make([]byte, 32))
	if err != nil {
		b.Fatalf("Failed to create poly1305 instance - Cause: %s", err)
	}
	msg := make([]byte, 1500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.Write(msg)
	}
}

func BenchmarkSum(b *testing.B) {
	var key [32]byte
	var tag [16]byte

	msg := make([]byte, 1500)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Sum(&tag, msg, &key)
	}
}
