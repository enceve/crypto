// Use of this source code is governed by a license
// that can be found in the LICENSE file.
// +build amd64,!appengine,!gccgo

// one BLAKE2b round:
//	- m0-m15: message index
//	- x5 - x13: 128 bit registers
//	- x5 = v0,v1, x6 = v2,v3, x7 = v4,v5, x8 = v6,v7
//	- x9 = v8,v9, x10 = v10,v11, x11 = v12,v13, x12 = v14,v15
//	- x13 is a tmp register
#define BLAKE2b_ROUND(m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15) \
	MOVLPS 8*m0(DX), X13; \
	MOVHPS 8*m1(DX), X13; \
	PADDQ X13, X5; \
	PADDQ X7, X5; \
	PXOR X5, X11; \
	MOVO X11, X13; \
	PSLLQ $32, X13; \
	PSRLQ $32, X11; \
	PXOR X13, X11; \
	PADDQ X11, X9; \
	PXOR X9, X7; \
	MOVO X7, X13; \
	PSLLQ $40, X13; \
	PSRLQ $24, X7; \
	PXOR X13, X7; \
	MOVLPS 8*m2(DX), X13; \
	MOVHPS 8*m3(DX), X13; \
	PADDQ X13, X6; \
	PADDQ X8, X6; \
	PXOR X6, X12; \
	MOVO X12, X13; \
	PSLLQ $32, X13; \
	PSRLQ $32, X12; \
	PXOR X13, X12; \
	PADDQ X12, X10; \
	PXOR X10, X8; \
	MOVO X8, X13; \
	PSLLQ $40, X13; \
	PSRLQ $24, X8; \
	PXOR X13, X8; \
	MOVLPS 8*m4(DX), X13; \
	MOVHPS 8*m5(DX), X13; \
	PADDQ X13, X6; \
	PADDQ X8, X6; \
	PXOR X6, X12; \
	MOVO X12, X13; \
	PSLLQ $48, X13; \
	PSRLQ $16, X12; \
	PXOR X13, X12; \
	PADDQ X12, X10; \
	PXOR X10, X8; \
	MOVO X8, X13; \
	PSLLQ $1, X13; \
	PSRLQ $63, X8; \
	PXOR X13, X8; \
	MOVHPS 8*m6(DX), X13; \
	MOVLPS 8*m7(DX), X13; \
	PADDQ X13, X5; \
	PADDQ X7, X5; \
	PXOR X5, X11; \
	MOVO X11, X13; \
	PSLLQ $48, X13; \
	PSRLQ $16, X11; \
	PXOR X13, X11; \
	PADDQ X11, X9; \
	PXOR X9, X7; \
	MOVO X7, X13; \
	PSLLQ $1, X13; \
	PSRLQ $63, X7; \
	PXOR X13, X7; \
	MOVO X7, X13; \
	MOVHLPS X7, X7; \
	MOVLHPS X8, X7; \
	MOVHLPS X8, X8; \
	MOVLHPS X13, X8; \
	MOVO X11, X13; \
	MOVHLPS X11, X11; \
	MOVLHPS X12, X11; \
	MOVHLPS X12, X12; \
	MOVLHPS X13, X12; \
	MOVLPS 8*m8(DX), X13; \
	MOVHPS 8*m9(DX), X13; \
	PADDQ X13, X5; \
	PADDQ X7, X5; \
	PXOR X5, X12; \
	MOVO X12, X13; \
	PSLLQ $32, X13; \
	PSRLQ $32, X12; \
	PXOR X13, X12; \
	PADDQ X12, X10; \
	PXOR X10, X7; \
	MOVO X7, X13; \
	PSLLQ $40, X13; \
	PSRLQ $24, X7; \
	PXOR X13, X7; \
	MOVLPS 8*m10(DX), X13; \
	MOVHPS 8*m11(DX), X13; \
	PADDQ X13, X6; \
	PADDQ X8, X6; \
	PXOR X6, X11; \
	MOVO X11, X13; \
	PSLLQ $32, X13; \
	PSRLQ $32, X11; \
	PXOR X13, X11; \
	PADDQ X11, X9; \
	PXOR X9, X8; \
	MOVO X8, X13; \
	PSLLQ $40, X13; \
	PSRLQ $24, X8; \
	PXOR X13, X8; \
	MOVLPS 8*m12(DX), X13; \
	MOVHPS 8*m13(DX), X13; \
	PADDQ X13, X6; \
	PADDQ X8, X6; \
	PXOR X6, X11; \
	MOVO X11, X13; \
	PSLLQ $48, X13; \
	PSRLQ $16, X11; \
	PXOR X13, X11; \
	PADDQ X11, X9; \
	PXOR X9, X8; \
	MOVO X8, X13; \
	PSLLQ $1, X13; \
	PSRLQ $63, X8; \
	PXOR X13, X8; \
	MOVHPS 8*m14(DX), X13; \
	MOVLPS 8*m15(DX), X13; \
	PADDQ X13, X5; \
	PADDQ X7, X5; \
	PXOR X5, X12; \
	MOVO X12, X13; \
	PSLLQ $48, X13; \
	PSRLQ $16, X12; \
	PXOR X13, X12; \
	PADDQ X12, X10; \
	PXOR X10, X7; \
	MOVO X7, X13; \
	PSLLQ $1, X13; \
	PSRLQ $63, X7; \
	PXOR X13, X7; \
	MOVO X7, X13; \
	MOVLHPS X7, X7; \
	MOVHLPS X8, X7; \
	MOVLHPS X8, X8; \
	MOVHLPS X13, X8; \
	MOVO X11, X13; \
	MOVLHPS X11, X11; \
	MOVHLPS X12, X11; \
	MOVLHPS X12, X12; \
	MOVHLPS X13, X12

// func blake2bCoreSSE2(hVal *[8]uint64, ctr *[2]uint64, flag uint64, msg *byte, iv *[8]uint64)
TEXT ·blake2bCoreSSE2(SB),4,$0-48
	MOVQ hVal+0(FP), AX
	MOVQ ctr+8(FP), BX
	MOVQ flag+16(FP), CX
	MOVQ msg+24(FP), DX
	MOVQ iv+32(FP), DI
	MOVO 0(BX), X0		// ctr
	MOVO 0(AX), X1		// h0,h1
	MOVO 16(AX), X2		// h2,h3
	MOVO 32(AX), X3		// h4,h5
	MOVO 48(AX), X4		// h6,h7
	MOVO X1, X5			// v0,v1
	MOVO X2, X6			// v2,v3
	MOVO X3, X7			// v4,v5
	MOVO X4, X8			// v6,v7
	MOVO 0(DI), X9		// iv0,iv1 (v8,v9)
	MOVO 16(DI), X10		// iv2,iv3 (v10,v11)
	MOVO 32(DI), X11		// iv4,iv5 (v12,v13)
	MOVO 48(DI), X12		// iv6,iv7 (v14,v15)
	PXOR X0, X11			// v12,v13 ^= ctr
	MOVQ	 CX, 0(BX)
	MOVO 0(BX), X13
	PXOR X13, X12		// v14 ^= flag (v15 ^= 0)
	BLAKE2b_ROUND(0, 2, 4, 6, 5, 7, 3, 1, 8, 10, 12, 14, 13, 15, 11, 9)
	BLAKE2b_ROUND(14, 4, 9, 13, 15, 6, 8, 10, 1, 0, 11, 5, 7, 3, 2, 12)
	BLAKE2b_ROUND(11, 12, 5, 15, 2, 13, 0, 8, 10, 3, 7, 9, 1, 4, 6, 14)
	BLAKE2b_ROUND(7, 3, 13, 11, 12, 14, 1, 9, 2, 5, 4, 15, 0, 8, 10, 6)
	BLAKE2b_ROUND(9, 5, 2, 10, 4, 15, 7, 0, 14, 11, 6, 3, 8, 13, 12, 1)
	BLAKE2b_ROUND(2, 6, 0, 8, 11, 3, 10, 12, 4, 7, 15, 1, 14, 9, 5, 13)
	BLAKE2b_ROUND(12, 1, 14, 4, 13, 10, 15, 5, 0, 6, 9, 8, 2, 11, 3, 7)
	BLAKE2b_ROUND(13, 7, 12, 3, 1, 9, 14, 11, 5, 15, 8, 2, 6, 10, 4, 0)
	BLAKE2b_ROUND(6, 14, 11, 0, 3, 8, 9, 15, 12, 13, 1, 10, 4, 5, 7, 2)
	BLAKE2b_ROUND(10, 8, 7, 1, 6, 5, 4, 2, 15, 9, 3, 13, 12, 0, 14, 11)
	BLAKE2b_ROUND(0, 2, 4, 6, 5, 7, 3, 1, 8, 10, 12, 14, 13, 15, 11, 9)
	BLAKE2b_ROUND(14, 4, 9, 13, 15, 6, 8, 10, 1, 0, 11, 5, 7, 3, 2, 12)
	PXOR X5, X1			// h0,h1 ^= v0,v1
	PXOR X9, X1			// h0,h1 ^= v8,v9
	PXOR X6, X2			// h2,h3 ^= v2,v3
	PXOR X10, X2			// h2,h3 ^= v10,v11
	PXOR X7, X3			// h4,h5 ^= v4,v5
	PXOR X11, X3			// h4,h5 ^= v12,v13
	PXOR X8, X4			// h6,h7 ^= v6,v7
	PXOR X12, X4			// h6,h7 ^= v14,v15
	MOVO X0, 0(BX)
	MOVO X1, 0(AX)
	MOVO X2, 16(AX)
	MOVO X3, 32(AX)
	MOVO X4, 48(AX)
	RET
	