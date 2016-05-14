package skein

// Convert a 32 byte array to 4 64 bit words
func toWords256(msg *[4]uint64, in *[Size256]byte) {
	msg[0] = uint64(in[0]) | uint64(in[1])<<8 | uint64(in[2])<<16 | uint64(in[3])<<24 |
		uint64(in[4])<<32 | uint64(in[5])<<40 | uint64(in[6])<<48 | uint64(in[7])<<56

	msg[1] = uint64(in[8]) | uint64(in[9])<<8 | uint64(in[10])<<16 | uint64(in[11])<<24 |
		uint64(in[12])<<32 | uint64(in[13])<<40 | uint64(in[14])<<48 | uint64(in[15])<<56

	msg[2] = uint64(in[16]) | uint64(in[17])<<8 | uint64(in[18])<<16 | uint64(in[19])<<24 |
		uint64(in[20])<<32 | uint64(in[21])<<40 | uint64(in[22])<<48 | uint64(in[23])<<56

	msg[3] = uint64(in[24]) | uint64(in[25])<<8 | uint64(in[26])<<16 | uint64(in[27])<<24 |
		uint64(in[28])<<32 | uint64(in[29])<<40 | uint64(in[30])<<48 | uint64(in[31])<<56
}

// Convert a 64 byte array to 8 64 bit words
func toWords512(msg *[8]uint64, in *[Size512]byte) {
	msg[0] = uint64(in[0]) | uint64(in[1])<<8 | uint64(in[2])<<16 | uint64(in[3])<<24 |
		uint64(in[4])<<32 | uint64(in[5])<<40 | uint64(in[6])<<48 | uint64(in[7])<<56

	msg[1] = uint64(in[8]) | uint64(in[9])<<8 | uint64(in[10])<<16 | uint64(in[11])<<24 |
		uint64(in[12])<<32 | uint64(in[13])<<40 | uint64(in[14])<<48 | uint64(in[15])<<56

	msg[2] = uint64(in[16]) | uint64(in[17])<<8 | uint64(in[18])<<16 | uint64(in[19])<<24 |
		uint64(in[20])<<32 | uint64(in[21])<<40 | uint64(in[22])<<48 | uint64(in[23])<<56

	msg[3] = uint64(in[24]) | uint64(in[25])<<8 | uint64(in[26])<<16 | uint64(in[27])<<24 |
		uint64(in[28])<<32 | uint64(in[29])<<40 | uint64(in[30])<<48 | uint64(in[31])<<56

	msg[4] = uint64(in[32]) | uint64(in[33])<<8 | uint64(in[34])<<16 | uint64(in[35])<<24 |
		uint64(in[36])<<32 | uint64(in[37])<<40 | uint64(in[38])<<48 | uint64(in[39])<<56

	msg[5] = uint64(in[40]) | uint64(in[41])<<8 | uint64(in[42])<<16 | uint64(in[43])<<24 |
		uint64(in[44])<<32 | uint64(in[45])<<40 | uint64(in[46])<<48 | uint64(in[47])<<56

	msg[6] = uint64(in[48]) | uint64(in[49])<<8 | uint64(in[50])<<16 | uint64(in[51])<<24 |
		uint64(in[52])<<32 | uint64(in[53])<<40 | uint64(in[54])<<48 | uint64(in[55])<<56

	msg[7] = uint64(in[56]) | uint64(in[57])<<8 | uint64(in[58])<<16 | uint64(in[59])<<24 |
		uint64(in[60])<<32 | uint64(in[61])<<40 | uint64(in[62])<<48 | uint64(in[63])<<56
}

// Convert a 128 byte array to 16 64 bit words
func toWords1024(msg *[16]uint64, in *[Size1024]byte) {
	msg[0] = uint64(in[0]) | uint64(in[1])<<8 | uint64(in[2])<<16 | uint64(in[3])<<24 |
		uint64(in[4])<<32 | uint64(in[5])<<40 | uint64(in[6])<<48 | uint64(in[7])<<56

	msg[1] = uint64(in[8]) | uint64(in[9])<<8 | uint64(in[10])<<16 | uint64(in[11])<<24 |
		uint64(in[12])<<32 | uint64(in[13])<<40 | uint64(in[14])<<48 | uint64(in[15])<<56

	msg[2] = uint64(in[16]) | uint64(in[17])<<8 | uint64(in[18])<<16 | uint64(in[19])<<24 |
		uint64(in[20])<<32 | uint64(in[21])<<40 | uint64(in[22])<<48 | uint64(in[23])<<56

	msg[3] = uint64(in[24]) | uint64(in[25])<<8 | uint64(in[26])<<16 | uint64(in[27])<<24 |
		uint64(in[28])<<32 | uint64(in[29])<<40 | uint64(in[30])<<48 | uint64(in[31])<<56

	msg[4] = uint64(in[32]) | uint64(in[33])<<8 | uint64(in[34])<<16 | uint64(in[35])<<24 |
		uint64(in[36])<<32 | uint64(in[37])<<40 | uint64(in[38])<<48 | uint64(in[39])<<56

	msg[5] = uint64(in[40]) | uint64(in[41])<<8 | uint64(in[42])<<16 | uint64(in[43])<<24 |
		uint64(in[44])<<32 | uint64(in[45])<<40 | uint64(in[46])<<48 | uint64(in[47])<<56

	msg[6] = uint64(in[48]) | uint64(in[49])<<8 | uint64(in[50])<<16 | uint64(in[51])<<24 |
		uint64(in[52])<<32 | uint64(in[53])<<40 | uint64(in[54])<<48 | uint64(in[55])<<56

	msg[7] = uint64(in[56]) | uint64(in[57])<<8 | uint64(in[58])<<16 | uint64(in[59])<<24 |
		uint64(in[60])<<32 | uint64(in[61])<<40 | uint64(in[62])<<48 | uint64(in[63])<<56

	msg[8] = uint64(in[64]) | uint64(in[65])<<8 | uint64(in[66])<<16 | uint64(in[67])<<24 |
		uint64(in[68])<<32 | uint64(in[69])<<40 | uint64(in[70])<<48 | uint64(in[71])<<56

	msg[9] = uint64(in[72]) | uint64(in[73])<<8 | uint64(in[74])<<16 | uint64(in[75])<<24 |
		uint64(in[76])<<32 | uint64(in[77])<<40 | uint64(in[78])<<48 | uint64(in[79])<<56

	msg[10] = uint64(in[80]) | uint64(in[81])<<8 | uint64(in[82])<<16 | uint64(in[83])<<24 |
		uint64(in[84])<<32 | uint64(in[85])<<40 | uint64(in[86])<<48 | uint64(in[87])<<56

	msg[11] = uint64(in[88]) | uint64(in[89])<<8 | uint64(in[90])<<16 | uint64(in[91])<<24 |
		uint64(in[92])<<32 | uint64(in[93])<<40 | uint64(in[94])<<48 | uint64(in[95])<<56

	msg[12] = uint64(in[96]) | uint64(in[97])<<8 | uint64(in[98])<<16 | uint64(in[99])<<24 |
		uint64(in[100])<<32 | uint64(in[101])<<40 | uint64(in[102])<<48 | uint64(in[103])<<56

	msg[13] = uint64(in[104]) | uint64(in[105])<<8 | uint64(in[106])<<16 | uint64(in[107])<<24 |
		uint64(in[108])<<32 | uint64(in[109])<<40 | uint64(in[110])<<48 | uint64(in[111])<<56

	msg[14] = uint64(in[112]) | uint64(in[113])<<8 | uint64(in[114])<<16 | uint64(in[115])<<24 |
		uint64(in[116])<<32 | uint64(in[117])<<40 | uint64(in[118])<<48 | uint64(in[119])<<56

	msg[15] = uint64(in[120]) | uint64(in[121])<<8 | uint64(in[122])<<16 | uint64(in[123])<<24 |
		uint64(in[124])<<32 | uint64(in[125])<<40 | uint64(in[126])<<48 | uint64(in[127])<<56
}

// Increment the tweak by the ctr argument
// Skein can consume messages up to 2^96 -1 bytes
func incTweak(tweak *[3]uint64, ctr uint64) {
	t0 := tweak[0]
	tweak[0] += ctr
	if tweak[0] < t0 {
		t1 := tweak[1]
		tweak[1] = (t1 & 0xFFFFFFFF00000000) | ((t1 + 1) & 0x00000000FFFFFFFF)
	}
}

// Xor`s the original message with output of the
// threefish encryption (msg)
func xor256(hVal *[5]uint64, message, msg *[4]uint64) {
	hVal[0] = message[0] ^ msg[0]
	hVal[1] = message[1] ^ msg[1]
	hVal[2] = message[2] ^ msg[2]
	hVal[3] = message[3] ^ msg[3]
}

// Xor`s the original message with output of the
// threefish encryption (msg)
func xor512(hVal *[9]uint64, message, msg *[8]uint64) {
	hVal[0] = message[0] ^ msg[0]
	hVal[1] = message[1] ^ msg[1]
	hVal[2] = message[2] ^ msg[2]
	hVal[3] = message[3] ^ msg[3]
	hVal[4] = message[4] ^ msg[4]
	hVal[5] = message[5] ^ msg[5]
	hVal[6] = message[6] ^ msg[6]
	hVal[7] = message[7] ^ msg[7]
}

// Xor`s the original message with output of the
// threefish encryption (msg)
func xor1024(hVal *[17]uint64, message, msg *[16]uint64) {
	hVal[0] = message[0] ^ msg[0]
	hVal[1] = message[1] ^ msg[1]
	hVal[2] = message[2] ^ msg[2]
	hVal[3] = message[3] ^ msg[3]
	hVal[4] = message[4] ^ msg[4]
	hVal[5] = message[5] ^ msg[5]
	hVal[6] = message[6] ^ msg[6]
	hVal[7] = message[7] ^ msg[7]
	hVal[8] = message[8] ^ msg[8]
	hVal[9] = message[9] ^ msg[9]
	hVal[10] = message[10] ^ msg[10]
	hVal[11] = message[11] ^ msg[11]
	hVal[12] = message[12] ^ msg[12]
	hVal[13] = message[13] ^ msg[13]
	hVal[14] = message[14] ^ msg[14]
	hVal[15] = message[15] ^ msg[15]
}

func (s *skein256) initialize(p *Params) {
	if p.HashSize < 1 || p.HashSize > Size256 {
		p.HashSize = Size256
	}
	s.hsize = p.HashSize

	if p.Key != nil {
		s.addParam(keyParam, p.Key)
	}
	s.addConfig(s.hsize)
	if p.PublicKey != nil {
		s.addParam(publicKeyParam, p.PublicKey)
	}
	if p.KeyID != nil {
		s.addParam(keyIDParam, p.KeyID)
	}
	if p.Nonce != nil {
		s.addParam(nonceParam, p.Nonce)
	}
	copy(s.initVal[:], s.hVal[:4])

	s.Reset()
}

// Add a parameter (secret key, nonce etc.) to the hash function
func (s *skein256) addParam(ptype uint64, param []byte) {
	s.tweak[0] = 0
	s.tweak[1] = ptype<<56 | firstBlock
	s.Write(param)
	s.finalize()
}

// Add the configuration block to the hash function
func (s *skein256) addConfig(hashsize int) {
	var c [32]byte
	copy(c[:], schemaId)

	bits := uint64(hashsize * 8)
	c[8] = byte(bits)
	c[9] = byte(bits >> 8)
	c[10] = byte(bits >> 16)
	c[11] = byte(bits >> 24)
	c[12] = byte(bits >> 32)
	c[13] = byte(bits >> 40)
	c[14] = byte(bits >> 48)
	c[15] = byte(bits >> 56)

	s.addParam(configParam, c[:])
}

func (s *skein512) initialize(p *Params) {
	if p.HashSize < 1 || p.HashSize > Size512 {
		p.HashSize = Size512
	}
	s.hsize = p.HashSize

	if p.Key != nil {
		s.addParam(keyParam, p.Key)
	}
	s.addConfig(s.hsize)
	if p.PublicKey != nil {
		s.addParam(publicKeyParam, p.PublicKey)
	}
	if p.KeyID != nil {
		s.addParam(keyIDParam, p.KeyID)
	}
	if p.Nonce != nil {
		s.addParam(nonceParam, p.Nonce)
	}
	copy(s.initVal[:], s.hVal[:8])

	s.Reset()
}

// Add a parameter (secret key, nonce etc.) to the hash function
func (s *skein512) addParam(ptype uint64, param []byte) {
	s.tweak[0] = 0
	s.tweak[1] = ptype<<56 | firstBlock
	s.Write(param)
	s.finalize()
}

// Add the configuration block to the hash function
func (s *skein512) addConfig(hashsize int) {
	var c [32]byte
	copy(c[:], schemaId)

	bits := uint64(hashsize * 8)
	c[8] = byte(bits)
	c[9] = byte(bits >> 8)
	c[10] = byte(bits >> 16)
	c[11] = byte(bits >> 24)
	c[12] = byte(bits >> 32)
	c[13] = byte(bits >> 40)
	c[14] = byte(bits >> 48)
	c[15] = byte(bits >> 56)

	s.addParam(configParam, c[:])
}

func (s *skein1024) initialize(p *Params) {
	if p.HashSize < 1 || p.HashSize > Size1024 {
		p.HashSize = Size1024
	}
	s.hsize = p.HashSize

	if p.Key != nil {
		s.addParam(keyParam, p.Key)
	}
	s.addConfig(s.hsize)
	if p.PublicKey != nil {
		s.addParam(publicKeyParam, p.PublicKey)
	}
	if p.KeyID != nil {
		s.addParam(keyIDParam, p.KeyID)
	}
	if p.Nonce != nil {
		s.addParam(nonceParam, p.Nonce)
	}
	copy(s.initVal[:], s.hVal[:16])

	s.Reset()
}

// Add a parameter (secret key, nonce etc.) to the hash function
func (s *skein1024) addParam(ptype uint64, param []byte) {
	s.tweak[0] = 0
	s.tweak[1] = ptype<<56 | firstBlock
	s.Write(param)
	s.finalize()
}

// Add the configuration block to the hash function
func (s *skein1024) addConfig(hashsize int) {
	var c [32]byte
	copy(c[:], schemaId)

	bits := uint64(hashsize * 8)
	c[8] = byte(bits)
	c[9] = byte(bits >> 8)
	c[10] = byte(bits >> 16)
	c[11] = byte(bits >> 24)
	c[12] = byte(bits >> 32)
	c[13] = byte(bits >> 40)
	c[14] = byte(bits >> 48)
	c[15] = byte(bits >> 56)

	s.addParam(configParam, c[:])
}
