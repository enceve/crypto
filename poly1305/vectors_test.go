// Use of this source code is governed by a license
// that can be found in the LICENSE file

package poly1305

import (
	"bytes"
	"encoding/hex"
	"testing"
)

type testVector struct {
	key, msg, tag string
}

var vectors = []testVector{
	// From: https://tools.ietf.org/html/rfc7539#section-2.5.2
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
			t.Fatalf("Test vector %d : Failed to decode key: %s", i, err)
		}
		msg, err := hex.DecodeString(v.msg)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to decode msg: %s", i, err)
		}
		tag, err := hex.DecodeString(v.tag)
		if err != nil {
			t.Fatalf("Test vector %d : Failed to decode tag: %s", i, err)
		}

		var sum [TagSize]byte
		var k [32]byte

		copy(k[:], key)
		Sum(&sum, msg, &k)
		if !bytes.Equal(sum[:], tag) {
			t.Fatalf("Test vector %d : Poly1305 Tags are not equal:\nFound:    %v\nExpected: %v", i, sum, tag)
		}

		p := New(&k)
		p.Write(msg)
		p.Sum(&sum)
		if !bytes.Equal(sum[:], tag) {
			t.Fatalf("Test vector %d : Poly1305 Tags are not equal:\nFound:    %v\nExpected: %v", i, sum[:], tag)
		}
	}
}
