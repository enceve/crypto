// Use of this source code is governed by a license
// that can be found in the LICENSE file

package skein

import (
	"encoding/hex"
	"hash"
	"testing"
)

type testVector struct {
	p         *Params
	msg, hash string
}

func checkHashes(t *testing.T, h hash.Hash, in, ref []byte, i int) {
	h.Write(in)
	sum := h.Sum(nil)
	if len(sum) != len(ref) {
		t.Fatalf("Test vector %d : Hash size does not match expected - found %d expected %d", i, len(sum), len(ref))
	}
	for j := range sum {
		if sum[j] != ref[j] {
			t.Fatalf("Test vector %d : Hash does not match:\nFound:    %v\nExpected: %v", i, hex.EncodeToString(sum), hex.EncodeToString(ref))
		}
	}
}

func decodeHex(t *testing.T, s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		if t == nil {
			panic(err)
		}
		t.Fatalf("Failed to decode hex: %s\nCaused by: %s", s, err)
	}
	return b
}

// test vectors from
// http://www.skein-hash.info/sites/default/files/skein_NIST_CD_121508.zip
var vectors = []testVector{
	// test vectors for Skein-256
	testVector{
		p:    &Params{BlockSize: StateSize256}, // without explicit hash size (check if default is used)
		msg:  "",
		hash: "C8877087DA56E072870DAA843F176E9453115929094C3A40C463A196C29BF7BA",
	},
	testVector{
		p: &Params{BlockSize: StateSize256, // without explicit hash size (check if default is used)
			Key: decodeHex(nil, "CB41F1706CDE09651203C2D0EFBADDF8")},
		msg:  "",
		hash: "886E4EFEFC15F06AA298963971D7A25398FFFE5681C84DB39BD00851F64AE29D",
	},
	testVector{
		p:    &Params{HashSize: StateSize256, BlockSize: StateSize256},
		msg:  "FF",
		hash: "0B98DCD198EA0E50A7A244C444E25C23DA30C10FC9A1F270A6637F1F34E67ED2",
	},
	testVector{
		p:    &Params{HashSize: StateSize256, BlockSize: StateSize256},
		msg:  "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0",
		hash: "8D0FA4EF777FD759DFD4044E6F6A5AC3C774AEC943DCFC07927B723B5DBF408B",
	},

	// test vectors for Skein-512
	testVector{
		p:   &Params{BlockSize: StateSize512}, // without explicit hash size (check if default is used)
		msg: "",
		hash: "BC5B4C50925519C290CC634277AE3D6257212395CBA733BBAD37A4AF0FA06AF4" +
			"1FCA7903D06564FEA7A2D3730DBDB80C1F85562DFCC070334EA4D1D9E72CBA7A",
	},
	testVector{
		p: &Params{BlockSize: StateSize512, // without explicit hash size (check if default is used)
			Key: decodeHex(nil, "CB41F1706CDE09651203C2D0EFBADDF847A0D315CB2E53FF8BAC41DA0002672E"+
				"920244C66E02D5F0DAD3E94C42BB65F0D14157DECF4105EF5609D5B0984457C1"+
				"935DF3061FF06E9F204192BA11E5BB2CAC0430C1C370CB3D113FEA5EC1021EB8"+
				"75E5946D7A96AC69A1626C6206B7252736F24253C9EE9B85EB852DFC814631346C"),
		},
		msg: "",
		hash: "9BD43D2A2FCFA92BECB9F69FAAB3936978F1B865B7E44338FC9C8F16ABA949BA" +
			"340291082834A1FC5AA81649E13D50CD98641A1D0883062BFE2C16D1FAA7E3AA",
	},
	testVector{
		p:   &Params{HashSize: StateSize512, BlockSize: StateSize512},
		msg: "FF",
		hash: "71B7BCE6FE6452227B9CED6014249E5BF9A9754C3AD618CCC4E0AAE16B316CC8" +
			"CA698D864307ED3E80B6EF1570812AC5272DC409b5A012DF2A579102F340617A",
	},
	testVector{
		p: &Params{HashSize: StateSize512, BlockSize: StateSize512},
		msg: "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
			"DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0",
		hash: "45863BA3BE0C4DFC27E75D358496F4AC9A736A505D9313B42B2F5EADA79FC17F" +
			"63861E947AFB1D056AA199575AD3F8C9A3CC1780B5E5FA4CAE050E989876625B",
	},

	// test vectors for Skein-1024
	testVector{
		p:   &Params{BlockSize: StateSize1024}, // without explicit hash size (check if default is used)
		msg: "",
		hash: "0FFF9563BB3279289227AC77D319B6FFF8D7E9F09DA1247B72A0A265CD6D2A62" +
			"645AD547ED8193DB48CFF847C06494A03F55666D3B47EB4C20456C9373C86297" +
			"D630D5578EBD34CB40991578F9F52B18003EFA35D3DA6553FF35DB91B81AB890" +
			"BEC1B189B7F52CB2A783EBB7D823D725B0B4A71F6824E88F68F982EEFC6D19C6",
	},
	testVector{
		p: &Params{BlockSize: StateSize1024, // without explicit hash size (check if default is used)
			Key: decodeHex(nil, "CB41F1706CDE09651203C2D0EFBADDF847A0D315CB2E53FF8BAC41DA0002672E"+
				"920244C66E02D5F0DAD3E94C42BB65F0D14157DECF4105EF5609D5B0984457C1"+
				"935DF3061FF06E9F204192BA11E5BB2CAC0430C1C370CB3D113FEA5EC1021EB8"+
				"75E5946D7A96AC69A1626C6206B7252736F24253C9EE9B85EB852DFC81463134"),
		},
		msg: "",
		hash: "BCF37B3459C88959D6B6B58B2BFE142CEF60C6F4EC56B0702480D7893A2B0595" +
			"AA354E87102A788B61996B9CBC1EADE7DAFBF6581135572C09666D844C90F066" +
			"B800FC4F5FD1737644894EF7D588AFC5C38F5D920BDBD3B738AEA3A3267D161E" +
			"D65284D1F57DA73B68817E17E381CA169115152B869C66B812BB9A84275303F0",
	},
	testVector{
		p: &Params{HashSize: StateSize1024, BlockSize: StateSize1024,
			Key: decodeHex(nil, "CB41F1706CDE09651203C2D0EFBADDF847A0D315CB2E53FF8BAC41DA0002672E"+
				"920244C66E02D5F0DAD3E94C42BB65F0D14157DECF4105EF5609D5B0984457C1"+
				"935DF3061FF06E9F204192BA11E5BB2CAC0430C1C370CB3D113FEA5EC1021EB8"+
				"75E5946D7A96AC69A1626C6206B7252736F24253C9EE9B85EB852DFC81463134"),
		},
		msg: "",
		hash: "BCF37B3459C88959D6B6B58B2BFE142CEF60C6F4EC56B0702480D7893A2B0595" +
			"AA354E87102A788B61996B9CBC1EADE7DAFBF6581135572C09666D844C90F066" +
			"B800FC4F5FD1737644894EF7D588AFC5C38F5D920BDBD3B738AEA3A3267D161E" +
			"D65284D1F57DA73B68817E17E381CA169115152B869C66B812BB9A84275303F0",
	},
	testVector{
		p:   &Params{HashSize: StateSize1024, BlockSize: StateSize1024},
		msg: "FF",
		hash: "E62C05802EA0152407CDD8787FDA9E35703DE862A4FBC119CFF8590AFE79250B" +
			"CCC8B3FAF1BD2422AB5C0D263FB2F8AFB3F796F048000381531B6F00D85161BC" +
			"0FFF4BEF2486B1EBCD3773FABF50AD4AD5639AF9040E3F29C6C931301BF79832" +
			"E9DA09857E831E82EF8B4691C235656515D437D2BDA33BCEC001C67FFDE15BA8",
	},
	testVector{
		p: &Params{HashSize: StateSize1024, BlockSize: StateSize1024},
		msg: "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
			"DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0" +
			"BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A0" +
			"9F9E9D9C9B9A999897969594939291908F8E8D8C8B8A89888786858483828180",
		hash: "1F3E02C46FB80A3FCD2DFBBC7C173800B40C60C2354AF551189EBF433C3D85F9" +
			"FF1803E6D920493179ED7AE7FCE69C3581A5A2F82D3E0C7A295574D0CD7D217C" +
			"484D2F6313D59A7718EAD07D0729C24851D7E7D2491B902D489194E6B7D369DB" +
			"0AB7AA106F0EE0A39A42EFC54F18D93776080985F907574F995EC6A37153A578",
	},
}

func TestSkein(t *testing.T) {
	for i, v := range vectors {
		p, in, ref := v.p, decodeHex(t, v.msg), decodeHex(t, v.hash)

		h, err := New(p)
		if err != nil {
			t.Fatal(err)
		}
		checkHashes(t, h, in, ref, i)

		if p.BlockSize == StateSize256 {
			if p.Key != nil {
				h, err := NewMAC256(p.HashSize, p.Key)
				if err != nil {
					t.Fatal(err)
				}
				checkHashes(t, h, in, ref, i)
			} else {
				h := New256(p.HashSize)
				if err != nil {
					t.Fatal(err)
				}
				checkHashes(t, h, in, ref, i)
			}
		}

		if p.BlockSize == StateSize512 {
			if p.Key != nil {
				h, err := NewMAC512(p.HashSize, p.Key)
				if err != nil {
					t.Fatal(err)
				}
				checkHashes(t, h, in, ref, i)
			} else {
				h := New512(p.HashSize)
				if err != nil {
					t.Fatal(err)
				}
				checkHashes(t, h, in, ref, i)

				if p.HashSize == HashSize512 {
					sum := Sum512(in)
					if len(sum) != len(ref) {
						t.Fatalf("Test vector %d : Hash size does not match expected - found %d expected %d", i, len(sum), len(ref))
					}
					for j := range sum {
						if sum[j] != ref[j] {
							t.Fatalf("Test vector %d : Hash does not match:\nFound:    %v\nExpected: %v", i, hex.EncodeToString(sum), hex.EncodeToString(ref))
						}
					}
				}
			}
		}

		if p.BlockSize == StateSize1024 {
			if p.Key != nil {
				h, err := NewMAC1024(p.HashSize, p.Key)
				if err != nil {
					t.Fatal(err)
				}
				checkHashes(t, h, in, ref, i)
			} else {
				h := New1024(p.HashSize)
				if err != nil {
					t.Fatal(err)
				}
				checkHashes(t, h, in, ref, i)
			}
		}
	}
}
