// Use of this source code is governed by a license
// that can be found in the LICENSE file.

// +build amd64,!gccgo,!appengine

// func chachaCore(dst *[64]byte, state *[16]uint32, rounds int)
TEXT ·chachaCore(SB),4,$0-24
	MOVQ state+8(FP), AX
	MOVQ dst+0(FP), BX
	MOVQ rounds+16(FP), CX
	MOVO 0(AX), X0
	MOVO 16(AX), X1
	MOVO 32(AX), X2
	MOVO 48(AX), X3
	MOVO X0, X4
	MOVO X1, X5
	MOVO X2, X6
	MOVO X3, X7
	loop:
		PADDL X5, X4
		PXOR X4, X7
		MOVO X7, X8
		PSLLL $16, X8
		PSRLL $16, X7
		PXOR X8, X7
		PADDL X7, X6
		PXOR X6, X5
		MOVO X5, X8
		PSLLL $12, X8
		PSRLL $20, X5
		PXOR X8, X5
		PADDL X5, X4
		PXOR X4, X7
		MOVO X7, X8
		PSLLL $8, X8
		PSRLL $24, X7
		PXOR X8, X7
		PADDL X7, X6
		PXOR X6, X5
		MOVO X5, X8
		PSLLL $7, X8
		PSRLL $25, X5
		PXOR X8, X5
		PSHUFL $57, X5, X5
		PSHUFL $78, X6, X6
		PSHUFL $147, X7, X7
		PADDL X5, X4
		PXOR X4, X7
		MOVO X7, X8
		PSLLL $16, X8
		PSRLL $16, X7
		PXOR X8, X7
		PADDL X7, X6
		PXOR X6, X5
		MOVO X5, X8
		PSLLL $12, X8
		PSRLL $20, X5
		PXOR X8, X5
		PADDL X5, X4
		PXOR X4, X7
		MOVO X7, X8
		PSLLL $8, X8
		PSRLL $24, X7
		PXOR X8, X7
		PADDL X7, X6
		PXOR X6, X5
		MOVO X5, X8
		PSLLL $7, X8
		PSRLL $25, X5
		PXOR X8, X5
		PSHUFL $147, X5, X5
		PSHUFL $78, X6, X6
		PSHUFL $57, X7, X7
		SUBQ $2, CX
		JNE loop
	PADDL X4, X0
	PADDL X5, X1
	PADDL X6, X2
	PADDL X7, X3
	MOVO X0, 0(BX)
	MOVO X1, 16(BX)
	MOVO X2, 32(BX)
	MOVO X3, 48(BX)
	RET
	
