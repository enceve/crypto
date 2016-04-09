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
