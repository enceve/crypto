// Use of this source code is governed by a license
// that can be found in the LICENSE file.

package chacha

import (
	"encoding/hex"
	"testing"
)

type testVector struct {
	key, nonce, msg, keystream, ciphertext string
	ctr                                    uint32
}

// Test vector from:
// https://tools.ietf.org/html/rfc7539#section-2.4.2
var chachaVectors = []testVector{
	testVector{
		key:   "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
		nonce: "000000000000004a00000000",
		msg: "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
			"73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
			"6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
			"637265656e20776f756c642062652069742e",
		keystream: "224f51f3401bd9e12fde276fb8631ded8c131f823d2c06" +
			"e27e4fcaec9ef3cf788a3b0aa372600a92b57974cded2b" +
			"9334794cba40c63e34cdea212c4cf07d41b769a6749f3f" +
			"630f4122cafe28ec4dc47e26d4346d70b98c73f3e9c53a" +
			"c40c5945398b6eda1a832c89c167eacd901d7e2bf363",
		ciphertext: "6e2e359a2568f98041ba0728dd0d6981" +
			"e97e7aec1d4360c20a27afccfd9fae0b" +
			"f91b65c5524733ab8f593dabcd62b357" +
			"1639d624e65152ab8f530c359f0861d8" +
			"07ca0dbf500d6a6156a38e088a22b65e" +
			"52bc514d16ccf806818ce91ab7793736" +
			"5af90bbf74a35be6b40b8eedf2785e42" +
			"874d",
		ctr: 1,
	},
}

type aeadTestVector struct {
	key, nonce, data, msg, ciphertext string
	tagSize                           int
}

// Test vector from:
// https://tools.ietf.org/html/rfc7539#section-2.8.2
var aeadVectors = []aeadTestVector{
	aeadTestVector{
		key: "808182838485868788898a8b8c8d8e8f" +
			"909192939495969798999a9b9c9d9e9f",
		nonce: "070000004041424344454647",
		data:  "50515253c0c1c2c3c4c5c6c7",
		msg: "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
			"73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
			"6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
			"637265656e20776f756c642062652069742e",
		ciphertext: "d31a8d34648e60db7b86afbc53ef7ec2" +
			"a4aded51296e08fea9e2b5a736ee62d6" +
			"3dbea45e8ca9671282fafb69da92728b" +
			"1a71de0a9e060b2905d6a5b67ecd3b36" +
			"92ddbd7f2d778b8c9803aee328091b58" +
			"fab324e4fad675945585808b4831d7bc" +
			"3ff4def08e4b7a9de576d26586cec64b" +
			"6116" +
			"1ae10b594f09e26a7e902ecbd0600691", // poly 1305 tag
		tagSize: TagSize,
	},
	aeadTestVector{
		key: "808182838485868788898a8b8c8d8e8f" +
			"909192939495969798999a9b9c9d9e9f",
		nonce: "070000004041424344454647",
		data:  "50515253c0c1c2c3c4c5c6c7",
		msg: "4c616469657320616e642047656e746c656d656e206f662074686520636c6173" +
			"73206f66202739393a204966204920636f756c64206f6666657220796f75206f" +
			"6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73" +
			"637265656e20776f756c642062652069742e",
		ciphertext: "d31a8d34648e60db7b86afbc53ef7ec2" +
			"a4aded51296e08fea9e2b5a736ee62d6" +
			"3dbea45e8ca9671282fafb69da92728b" +
			"1a71de0a9e060b2905d6a5b67ecd3b36" +
			"92ddbd7f2d778b8c9803aee328091b58" +
			"fab324e4fad675945585808b4831d7bc" +
			"3ff4def08e4b7a9de576d26586cec64b" +
			"6116" +
			"1ae10b594f09e26a7e902ecb", // poly 1305 tag
		tagSize: 12,
	},
}

func TestVectors(t *testing.T) {
	for i, v := range chachaVectors {
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex key: %s", i, err)
		}
		nonce, err := hex.DecodeString(v.nonce)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex nonce: %s", i, err)
		}
		msg, err := hex.DecodeString(v.msg)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex msg: %s", i, err)
		}
		keystream, err := hex.DecodeString(v.keystream)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex keystream: %s", i, err)
		}
		ciphertext, err := hex.DecodeString(v.ciphertext)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex ciphertext: %s", i, err)
		}
		c, err := New(key, nonce)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to create cipher instance: %s", i, err)
		}
		ch := c.(*chacha20)
		ch.state[12] = v.ctr

		buf := make([]byte, len(keystream))
		c.XORKeyStream(buf, msg)

		for j := range buf {
			if buf[j] != ciphertext[j] {
				t.Fatalf("Test vector %d :\nUnexpected keystream:\nFound:    %v\nExpected: %v", i, hex.EncodeToString(buf), hex.EncodeToString(ciphertext))
			}
		}
		for i := range buf {
			buf[i] ^= msg[i]
		}
		for j := range buf {
			if buf[j] != keystream[j] {
				t.Fatalf("Test vector %d :\nUnexpected keystream:\nFound:    %v\nExpected: %v", i, hex.EncodeToString(buf), hex.EncodeToString(keystream))
			}
		}
	}
}

func TestAEADVectors(t *testing.T) {
	for i, v := range aeadVectors {
		key, err := hex.DecodeString(v.key)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex key: %s", i, err)
		}
		nonce, err := hex.DecodeString(v.nonce)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex nonce: %s", i, err)
		}
		msg, err := hex.DecodeString(v.msg)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex msg: %s", i, err)
		}
		data, err := hex.DecodeString(v.data)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex data: %s", i, err)
		}
		ciphertext, err := hex.DecodeString(v.ciphertext)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to decode hex ciphertext: %s", i, err)
		}
		c, err := NewAEAD(key, v.tagSize)
		if err != nil {
			t.Fatalf("Test vector %d: Failed to create AEAD instance: %s", i, err)
		}

		buf := make([]byte, len(ciphertext))
		c.Seal(buf, nonce, msg, data)

		if len(buf) != len(ciphertext) {
			t.Fatalf("Test vector %d Seal: length of buf and ciphertext does not match - found %d expected %d", i, len(buf), len(ciphertext))
		}
		for j, v := range ciphertext {
			if v != buf[j] {
				t.Fatalf("TestVector %d Seal failed:\nFound   : %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(ciphertext))
			}
		}

		buf, err = c.Open(buf, nonce, buf, data)

		if err != nil {
			t.Fatalf("TestVector %d: Open failed - Cause: %s", i, err)
		}
		if len(buf) != len(msg) {
			t.Fatalf("Test vector %d Open: length of buf and msg does not match - found %d expected %d", i, len(buf), len(msg))
		}
		for j, v := range msg {
			if v != buf[j] {
				t.Fatalf("TestVector %d Open failed:\nFound   : %s\nExpected: %s", i, hex.EncodeToString(buf), hex.EncodeToString(msg))
			}
		}
	}
}
