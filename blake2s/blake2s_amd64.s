// Use of this source code is governed by a license
// that can be found in the LICENSE file.
// +build amd64,!appengine,!gccgo

#define BLAKE2s_G1() \
	PSHUFL $21, X7, X7; \
	PSHUFL $69, X6, X6; \
	PSHUFL $81, X5, X5; \
	POR X7, X4; \
	POR X6, X4; \
	POR X5, X4; \
	PADDL X4, X0; \
	PADDL X1, X0; \
	PXOR X0, X3; \
	MOVO X3, X5; \
	PSLLL $16, X5; \
	PSRLL $16, X3; \
	PXOR X5, X3; \
	PADDL X3, X2; \
	PXOR X2, X1; \
	MOVO X1, X5; \
	PSLLL $20, X5; \
	PSRLL $12, X1; \
	PXOR X5, X1

#define BLAKE2s_G2(s0 , s1 , s2) \
	PSHUFL $21, X7, X7; \
	PSHUFL $69, X6, X6; \
	PSHUFL $81, X5, X5; \
	POR X7, X4; \
	POR X6, X4; \
	POR X5, X4; \
	PADDL X4, X0; \
	PADDL X1, X0; \
	PXOR X0, X3; \
	MOVO X3, X5; \
	PSLLL $24, X5; \
	PSRLL $8, X3; \
	PXOR X5, X3; \
	PADDL X3, X2; \
	PXOR X2, X1; \
	MOVO X1, X5; \
	PSLLL $25, X5; \
	PSRLL $7, X1; \
	PXOR X5, X1; \
	PSHUFL $s0, X1, X1; \
	PSHUFL $s1, X2, X2; \
	PSHUFL $s2, X3, X3

// func blake2sCoreSSE2(hVal *[8]uint32, ctr *[2]uint32, flag uint32, msg *byte, iv *[8]uint32)
TEXT ·blake2sCoreSSE2(SB),4,$0-36
	MOVQ hVal+0(FP), AX
	MOVQ ctr+8(FP), BX
	MOVLQZX flag+16(FP), CX
	MOVQ msg+24(FP), DX
	MOVQ iv+32(FP), DI
	MOVQ 0(BX), SI
	MOVO 0(AX), X8
	MOVO 16(AX), X9
	MOVO 0(DI), X2
	MOVO 16(DI), X3
	MOVO X8, X0
	MOVO X9, X1
	MOVO X2, X2
	MOVO X3, X3
	ADDQ $64, SI
	MOVQ SI, X5
	MOVQ CX, X6
	MOVLHPS X6, X5
	PXOR X5, X3
	// BLAKE2s_Round(0, 2, 4, 6, 5, 7, 3, 1, 8, 10, 12, 14, 13, 15, 11, 9)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x22 // MOVD xmm4, [rdx]		
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x08 // MOVD xmm5, [rdx + 8]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x10 // MOVD xmm6, [rdx + 16]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x18 // MOVD xmm7, [rdx + 24]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x04 // MOVD xmm4, [rdx + 4]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x0C // MOVD xmm5, [rdx + 12]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x14 // MOVD xmm6, [rdx + 20]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x1C // MOVD xmm7, [rdx + 28]
	BLAKE2s_G2(57, 78, 147)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x20 // MOVD xmm4, [rdx + 32]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x28 // MOVD xmm5, [rdx + 40]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x30 // MOVD xmm6, [rdx + 48]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x38 // MOVD xmm7, [rdx + 56]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x24 // MOVD xmm4, [rdx + 36]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x2C // MOVD xmm5, [rdx + 44]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x34 // MOVD xmm6, [rdx + 52]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x3C // MOVD xmm7, [rdx + 60]
	BLAKE2s_G2(147, 78, 57)
	// BLAKE2s_Round(14, 4, 9, 13, 15, 6, 8, 10, 1, 0, 11, 5, 7, 3, 2, 12)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x38 // MOVD xmm4, [rdx + 56]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x10 // MOVD xmm5, [rdx + 16]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x24 // MOVD xmm6, [rdx + 36]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x34 // MOVD xmm7, [rdx + 52]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x28 // MOVD xmm4, [rdx + 40]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x20 // MOVD xmm5, [rdx + 32]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x3C // MOVD xmm6, [rdx + 60]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x18 // MOVD xmm7, [rdx + 24]
	BLAKE2s_G2(57, 78, 147)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x04 // MOVD xmm4, [rdx + 4]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x2A // MOVD xmm5, [rdx]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x2C // MOVD xmm6, [rdx + 44]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x14 // MOVD xmm7, [rdx + 20]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x30 // MOVD xmm4, [rdx + 48]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x08 // MOVD xmm5, [rdx + 8]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x1C // MOVD xmm6, [rdx + 28]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x0C // MOVD xmm7, [rdx + 12]
	BLAKE2s_G2(147, 78, 57)
	// BLAKE2s_Round(11, 12, 5, 15, 2, 13, 0, 8, 10, 3, 7, 9, 1, 4, 6, 14)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x2C // MOVD xmm4, [rdx + 44]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x30 // MOVD xmm5, [rdx + 48]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x14 // MOVD xmm6, [rdx + 20]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x3C // MOVD xmm7, [rdx + 60]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x20 // MOVD xmm4, [rdx + 32]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x2A // MOVD xmm5, [rdx]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x08 // MOVD xmm6, [rdx + 8]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x34 // MOVD xmm7, [rdx + 52]
	BLAKE2s_G2(57, 78, 147)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x28 // MOVD xmm4, [rdx + 40]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x0C // MOVD xmm5, [rdx + 12]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x1C // MOVD xmm6, [rdx + 28]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x24 // MOVD xmm7, [rdx + 36]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x38 // MOVD xmm4, [rdx + 56]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x18 // MOVD xmm5, [rdx + 24]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x04 // MOVD xmm6, [rdx + 4]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x10 // MOVD xmm7, [rdx + 16]
	BLAKE2s_G2(147, 78, 57)
	// BLAKE2s_Round(7, 3, 13, 11, 12, 14, 1, 9, 2, 5, 4, 15, 0, 8, 10, 6)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x1C // MOVD xmm4, [rdx + 28]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x0C // MOVD xmm5, [rdx + 12]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x34 // MOVD xmm6, [rdx + 52]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x2C // MOVD xmm7, [rdx + 44]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x24 // MOVD xmm4, [rdx + 36]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x04 // MOVD xmm5, [rdx + 4]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x30 // MOVD xmm6, [rdx + 48]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x38 // MOVD xmm7, [rdx + 56]
	BLAKE2s_G2(57, 78, 147)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x08 // MOVD xmm4, [rdx + 8]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x14 // MOVD xmm5, [rdx + 20]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x10 // MOVD xmm6, [rdx + 16]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x3C // MOVD xmm7, [rdx + 60]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x18 // MOVD xmm4, [rdx + 24]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x28 // MOVD xmm5, [rdx + 40]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x32 // MOVD xmm6, [rdx]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x20 // MOVD xmm7, [rdx + 32]
	BLAKE2s_G2(147, 78, 57)
	// BLAKE2s_Round(9, 5, 2, 10, 4, 15, 7, 0, 14, 11, 6, 3, 8, 13, 12, 1)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x24 // MOVD xmm4, [rdx + 36]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x14 // MOVD xmm5, [rdx + 20]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x08 // MOVD xmm6, [rdx + 8]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x28 // MOVD xmm7, [rdx + 40]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x22 // MOVD xmm4, [rdx]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x1C // MOVD xmm5, [rdx + 28]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x10 // MOVD xmm6, [rdx + 16]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x3C // MOVD xmm7, [rdx + 60])
	BLAKE2s_G2(57, 78, 147)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x38 // MOVD xmm4, [rdx + 56]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x2C // MOVD xmm5, [rdx + 44]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x18 // MOVD xmm6, [rdx + 24]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x0C // MOVD xmm7, [rdx + 12]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x04 // MOVD xmm4, [rdx + 4]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x30 // MOVD xmm5, [rdx + 48]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x20 // MOVD xmm6, [rdx + 32]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x34 // MOVD xmm7, [rdx + 52]
	BLAKE2s_G2(147, 78, 57)
	// BLAKE2s_Round(2, 6, 0, 8, 11, 3, 10, 12, 4, 7, 15, 1, 14, 9, 5, 13)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x08 // MOVD xmm4, [rdx + 8]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x18 // MOVD xmm5, [rdx + 24]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x32 // MOVD xmm6, [rdx]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x20 // MOVD xmm7, [rdx + 32]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x30 // MOVD xmm4, [rdx + 48]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x28 // MOVD xmm5, [rdx + 40]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x2C // MOVD xmm6, [rdx + 44]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x0C // MOVD xmm7, [rdx + 12]
	BLAKE2s_G2(57, 78, 147)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x10 // MOVD xmm4, [rdx + 16]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x1C // MOVD xmm5, [rdx + 28]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x3C // MOVD xmm6, [rdx + 60]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x04 // MOVD xmm7, [rdx + 4]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x34 // MOVD xmm4, [rdx + 52]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x14 // MOVD xmm5, [rdx + 20]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x38 // MOVD xmm6, [rdx + 56]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x24 // MOVD xmm7, [rdx + 36]
	BLAKE2s_G2(147, 78, 57)
	// BLAKE2s_Round(12, 1, 14, 4, 13, 10, 15, 5, 0, 6, 9, 8, 2, 11, 3, 7)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x30 // MOVD xmm4, [rdx + 48]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x04 // MOVD xmm5, [rdx + 4]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x38 // MOVD xmm6, [rdx + 56]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x10 // MOVD xmm7, [rdx + 16]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x14 // MOVD xmm4, [rdx + 20]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x3C // MOVD xmm5, [rdx + 60]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x34 // MOVD xmm6, [rdx + 52]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x28 // MOVD xmm7, [rdx + 40]
	BLAKE2s_G2(57, 78, 147)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x22 // MOVD xmm4, [rdx]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x18 // MOVD xmm5, [rdx + 24]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x24 // MOVD xmm6, [rdx + 36]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x20 // MOVD xmm7, [rdx + 32]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x1C // MOVD xmm4, [rdx + 28]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x0C // MOVD xmm5, [rdx + 12]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x08 // MOVD xmm6, [rdx + 8]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x2C // MOVD xmm7, [rdx + 44]
	BLAKE2s_G2(147, 78, 57)
	// BLAKE2s_Round(13, 7, 12, 3, 1, 9, 14, 11, 5, 15, 8, 2, 6, 10, 4, 0)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x34 // MOVD xmm4, [rdx + 52]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x1C // MOVD xmm5, [rdx + 28]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x30 // MOVD xmm6, [rdx + 48]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x0C // MOVD xmm7, [rdx + 12]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x2C // MOVD xmm4, [rdx + 44]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x38 // MOVD xmm5, [rdx + 56]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x04 // MOVD xmm6, [rdx + 4]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x24 // MOVD xmm7, [rdx + 36]
	BLAKE2s_G2(57, 78, 147)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x14 // MOVD xmm4, [rdx + 20]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x3C // MOVD xmm5, [rdx + 60]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x20 // MOVD xmm6, [rdx + 32]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x08 // MOVD xmm7, [rdx + 8]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x22 // MOVD xmm4, [rdx]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x10 // MOVD xmm5, [rdx + 16]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x18 // MOVD xmm6, [rdx + 24]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x28 // MOVD xmm7, [rdx + 40]
	BLAKE2s_G2(147, 78, 57)
	// BLAKE2s_Round(6, 14, 11, 0, 3, 8, 9, 15, 12, 13, 1, 10, 4, 5, 7, 2)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x18 // MOVD xmm4, [rdx + 24]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x38 // MOVD xmm5, [rdx + 56]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x2C // MOVD xmm6, [rdx + 44]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x3A // MOVD xmm7, [rdx]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x3C // MOVD xmm4, [rdx + 60]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x24 // MOVD xmm5, [rdx + 36]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x0C // MOVD xmm6, [rdx + 12]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x20 // MOVD xmm7, [rdx + 32]
	BLAKE2s_G2(57, 78, 147)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x30 // MOVD xmm4, [rdx + 48]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x34 // MOVD xmm5, [rdx + 52]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x04 // MOVD xmm6, [rdx + 4]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x28 // MOVD xmm7, [rdx + 40]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x08 // MOVD xmm4, [rdx + 8]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x1C // MOVD xmm5, [rdx + 28]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x10 // MOVD xmm6, [rdx + 16]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x14 // MOVD xmm7, [rdx + 20]
	BLAKE2s_G2(147, 78, 57)
	// BLAKE2s_Round(10, 8, 7, 1, 6, 5, 4, 2, 15, 9, 3, 13, 12, 0, 14, 11)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x28 // MOVD xmm4, [rdx + 40]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x20 // MOVD xmm5, [rdx + 32]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x1C // MOVD xmm6, [rdx + 28]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x04 // MOVD xmm7, [rdx + 4]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x08 // MOVD xmm4, [rdx + 8]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x10 // MOVD xmm5, [rdx + 16]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x18 // MOVD xmm6, [rdx + 24]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x14 // MOVD xmm7, [rdx + 20]
	BLAKE2s_G2(57, 78, 147)
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x3C // MOVD xmm4, [rdx + 60]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x24 // MOVD xmm5, [rdx + 36]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x0C // MOVD xmm6, [rdx + 12]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x7A; BYTE $0x34 // MOVD xmm7, [rdx + 52]
	BLAKE2s_G1()
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x62; BYTE $0x2C // MOVD xmm4, [rdx + 44]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x6A; BYTE $0x38 // MOVD xmm5, [rdx + 56]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x72; BYTE $0x30 // MOVD xmm6, [rdx + 48]
	BYTE $0x66; BYTE $0x0F; BYTE $0x6E; BYTE $0x3A // MOVD xmm7, [rdx]
	BLAKE2s_G2(147, 78, 57)
	PXOR X0, X8
	PXOR X2, X8
	PXOR X1, X9
	PXOR X3, X9
	MOVO X8, 0(AX)
	MOVO X9, 16(AX)
	MOVQ SI, 0(BX)
	RET
	