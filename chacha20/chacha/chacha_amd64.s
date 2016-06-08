// Use of this source code is governed by a license
// that can be found in the LICENSE file.

#define ROTL32(n, v , t) \
 	MOVO v, t; \
	PSLLL $n, t; \
	PSRLL $(32-n), v; \
	PXOR t, v

#define ROUND64(v0 , v1 , v2 , v3 , t0) \
	PADDL v1, v0; \
	PXOR v0, v3; \
	ROTL32(16, v3, t0); \
	PADDL v3, v2; \
	PXOR v2, v1; \
	ROTL32(12, v1, t0); \
	PADDL v1, v0; \
	PXOR v0, v3; \
	ROTL32(8, v3, t0); \
	PADDL v3, v2; \
	PXOR v2, v1; \
	ROTL32(7, v1, t0); \
	PSHUFL $57, v1, v1; \
	PSHUFL $78, v2, v2; \
	PSHUFL $147, v3, v3; \
	PADDL v1, v0; \
	PXOR v0, v3; \
	ROTL32(16, v3, t0); \
	PADDL v3, v2; \
	PXOR v2, v1; \
	ROTL32(12, v1, t0); \
	PADDL v1, v0; \
	PXOR v0, v3; \
	ROTL32(8, v3, t0); \
	PADDL v3, v2; \
	PXOR v2, v1; \
	ROTL32(7, v1, t0); \
	PSHUFL $147, v1, v1; \
	PSHUFL $78, v2, v2; \
	PSHUFL $57, v3, v3
	
#define ROUND128(v0, v1, v2, v3, v4, v5, v6, v7, t0, t1) \
	PADDL v1, v0; \
	PADDL v5, v4; \
	PXOR v0, v3; \
	PXOR v4, v7; \
	ROTL32(16, v3, t0); \
	ROTL32(16, v7, t1); \
	PADDL v3, v2; \
	PADDL v7, v6; \
	PXOR v2, v1; \
	PXOR v6, v5; \
	ROTL32(12, v1, t0); \
	ROTL32(12, v5, t1); \
	PADDL v1, v0; \
	PADDL v5, v4; \
	PXOR v0, v3; \
	PXOR v4, v7; \
	ROTL32(8, v3, t0); \
	ROTL32(8, v7, t1); \
	PADDL v3, v2; \
	PADDL v7, v6; \
	PXOR v2, v1; \
	PXOR v6, v5; \
	ROTL32(7, v1, t0); \
	ROTL32(7, v5, t1); \
	PSHUFL $57, v1, v1; \
	PSHUFL $57, v5, v5; \
	PSHUFL $78, v2, v2; \
	PSHUFL $78, v6, v6; \
	PSHUFL $147, v3, v3; \
	PSHUFL $147, v7, v7; \
	PADDL v1, v0; \
	PADDL v5, v4; \
	PXOR v0, v3; \
	PXOR v4, v7; \
	ROTL32(16, v3, t0); \
	ROTL32(16, v7, t1); \
	PADDL v3, v2; \
	PADDL v7, v6; \
	PXOR v2, v1; \
	PXOR v6, v5; \
	ROTL32(12, v1, t0); \
	ROTL32(12, v5, t1); \
	PADDL v1, v0; \
	PADDL v5, v4; \
	PXOR v0, v3; \
	PXOR v4, v7; \
	ROTL32(8, v3, t0); \
	ROTL32(8, v7, t1); \
	PADDL v3, v2; \
	PADDL v7, v6; \
	PXOR v2, v1; \
	PXOR v6, v5; \
	ROTL32(7, v1, t0); \
	ROTL32(7, v5, t1); \
	PSHUFL $147, v1, v1; \
	PSHUFL $147, v5, v5; \
	PSHUFL $78, v2, v2; \
	PSHUFL $78, v6, v6; \
	PSHUFL $57, v3, v3; \
	PSHUFL $57, v7, v7
	
#define ROUND192(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, t0, t1, t2) \
	PADDL v1, v0; \
	PADDL v5, v4; \
	PADDL v9, v8; \
	PXOR v0, v3; \
	PXOR v4, v7; \
	PXOR v8, v11; \
	ROTL32(16, v3, t0); \
	ROTL32(16, v7, t1); \
	ROTL32(16, v11, t2); \
	PADDL v3, v2; \
	PADDL v7, v6; \
	PADDL v11, v10; \
	PXOR v2, v1; \
	PXOR v6, v5; \
	PXOR v10, v9; \
	ROTL32(12, v1, t0); \
	ROTL32(12, v5, t1); \
	ROTL32(12, v9, t2); \
	PADDL v1, v0; \
	PADDL v5, v4; \
	PADDL v9, v8; \
	PXOR v0, v3; \
	PXOR v4, v7; \
	PXOR v8, v11; \
	ROTL32(8, v3, t0); \
	ROTL32(8, v7, t1); \
	ROTL32(8, v11, t2); \
	PADDL v3, v2; \
	PADDL v7, v6; \
	PADDL v11, v10; \
	PXOR v2, v1; \
	PXOR v6, v5; \
	PXOR v10, v9; \
	ROTL32(7, v1, t0); \
	ROTL32(7, v5, t1); \
	ROTL32(7, v9, t2); \
	PSHUFL $57, v1, v1; \
	PSHUFL $57, v5, v5; \
	PSHUFL $57, v9, v9; \
	PSHUFL $78, v2, v2; \
	PSHUFL $78, v6, v6; \
	PSHUFL $78, v10, v10; \
	PSHUFL $147, v3, v3; \
	PSHUFL $147, v7, v7; \
	PSHUFL $147, v11, v11; \
	PADDL v1, v0; \
	PADDL v5, v4; \
	PADDL v9, v8; \
	PXOR v0, v3; \
	PXOR v4, v7; \
	PXOR v8, v11; \
	ROTL32(16, v3, t0); \
	ROTL32(16, v7, t1); \
	ROTL32(16, v11, t2); \
	PADDL v3, v2; \
	PADDL v7, v6; \
	PADDL v11, v10; \
	PXOR v2, v1; \
	PXOR v6, v5; \
	PXOR v10, v9; \
	ROTL32(12, v1, t0); \
	ROTL32(12, v5, t1); \
	ROTL32(12, v9, t2); \
	PADDL v1, v0; \
	PADDL v5, v4; \
	PADDL v9, v8; \
	PXOR v0, v3; \
	PXOR v4, v7; \
	PXOR v8, v11; \
	ROTL32(8, v3, t0); \
	ROTL32(8, v7, t1); \
	ROTL32(8, v11, t2); \
	PADDL v3, v2; \
	PADDL v7, v6; \
	PADDL v11, v10; \
	PXOR v2, v1; \
	PXOR v6, v5; \
	PXOR v10, v9; \
	ROTL32(7, v1, t0); \
	ROTL32(7, v5, t1); \
	ROTL32(7, v9, t2); \
	PSHUFL $147, v1, v1; \
	PSHUFL $147, v5, v5; \
	PSHUFL $147, v9, v9; \
	PSHUFL $78, v2, v2; \
	PSHUFL $78, v6, v6; \
	PSHUFL $78, v10, v10; \
	PSHUFL $57, v3, v3; \
	PSHUFL $57, v7, v7; \
	PSHUFL $57, v11, v11
	
#define XOR64(dst, src, off, v0 , v1 , v2 , v3 , t0, t1) \
	MOVOU 0+off(src), t0; \
	PXOR v0, t0; \
	MOVOU t0, 0+off(dst); \
	MOVOU 16+off(src), t1; \
	PXOR v1, t1; \
	MOVOU t1, 16+off(dst); \
	MOVOU 32+off(src), t0; \
	PXOR v2, t0; \
	MOVOU t0, 32+off(dst); \
	MOVOU 48+off(BX), t1; \
	PXOR v3, t1; \
	MOVOU t1, 48+off(dst)

// func Core(dst *[64]byte, state *[16]uint32, rounds int)
TEXT ·Core(SB),4,$0-24
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
		ROUND64(X4, X5, X6, X7, X8)
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

// func xorBlocksSSE64(dst *byte, src *byte, state *[16]uint32, rounds int)
TEXT ·xorBlocksSSE64(SB),4,$0-32
	MOVQ dst+0(FP), AX
	MOVQ src+8(FP), BX
	MOVQ state+16(FP), CX
	MOVQ rounds+24(FP), DX
	MOVO 0(CX), X0
	MOVO 16(CX), X1
	MOVO 32(CX), X2
	MOVO 48(CX), X3
	MOVL 48(CX), DI
	MOVO X0, X5
	MOVO X1, X6
	MOVO X2, X7
	MOVO X3, X8
	loop:
		ROUND64(X5, X6, X7, X8, X9)
		SUBQ $2, DX
		JNE loop
	PADDL X0, X5
	PADDL X1, X6
	PADDL X2, X7
	PADDL X3, X8
	XOR64(AX, BX, 0, X5, X6, X7, X8, X9, X10)
	ADDL $1, DI
	MOVL DI, 48(CX)
	RET

// func xorBlocksSSE128(dst *byte, src *byte, state *[16]uint32, rounds int)
TEXT ·xorBlocksSSE128(SB),4,$0-32
	MOVQ dst+0(FP), AX
	MOVQ src+8(FP), BX
	MOVQ state+16(FP), CX
	MOVQ rounds+24(FP), DX
	MOVO 0(CX), X0
	MOVO 16(CX), X1
	MOVO 32(CX), X2
	MOVO 48(CX), X3
	MOVO X0, X4
	MOVO X1, X5
	MOVO X2, X6
	MOVO X3, X7
	MOVL 48(CX), DI
	ADDL $1, DI
	MOVL DI, 48(CX)
	MOVO 48(CX), X8
	MOVO X0, X9
	MOVO X1, X10
	MOVO X2, X11
	MOVO X8, X12
	loop:
		ROUND128(X4, X5, X6, X7, X9, X10, X11, X12, X14, X15)
		SUBQ $2, DX
		JNE loop
	PADDL X0, X4
	PADDL X1, X5
	PADDL X2, X6
	PADDL X3, X7
	XOR64(AX, BX, 0, X4, X5, X6, X7, X14, X15)
	PADDL X0, X9
	PADDL X1, X10
	PADDL X2, X11
	PADDL X8, X12
	XOR64(AX, BX, 64, X9, X10, X11, X12, X14, X15)
	ADDL $1, DI
	MOVL DI, 48(CX)
	RET

// func xorBlocksSSE192(dst *byte, src *byte, length uint64, state *[16]uint32, rounds int)
TEXT ·xorBlocksSSE192(SB),4,$0-40
	MOVQ dst+0(FP), AX
	MOVQ src+8(FP), BX
	MOVQ length+16(FP), DX
	MOVQ state+24(FP), CX
	MOVQ rounds+32(FP), SI
	MOVO 0(CX), X0
	MOVO 16(CX), X1
	MOVO 32(CX), X2
	xor_loop:
		MOVO X0, X3
		MOVO X1, X4
		MOVO X2, X5
		MOVO 48(CX), X0
		MOVO X0, X6
		MOVL 48(CX), DI
		ADDL $1, DI
		MOVL DI, 48(CX)
		MOVO X3, X7
		MOVO X4, X8
		MOVO X5, X9
		MOVO 48(CX), X1
		MOVO X1, X10
		MOVL 48(CX), DI
		ADDL $1, DI
		MOVL DI, 48(CX)
		MOVO X3, X11
		MOVO X4, X12
		MOVO X5, X13
		MOVO 48(CX), X2
		MOVO X2, X14
		MOVQ SI, R9
		chacha_loop:
			ROUND192(X3, X4, X5, X6, X7, X8, X9, X10, X11, X12, X13, X14, X15, X15, X15)
			SUBQ $2, R9
		JNE chacha_loop
	PADDL X0, X6
	PADDL X1, X10
	PADDL X2, X14
	MOVO 0(CX), X0
	MOVO 16(CX), X1
	MOVO 32(CX), X2
	PADDL X0, X3
	PADDL X1, X4
	PADDL X2, X5
	XOR64(AX, BX, 0, X3, X4, X5, X6, X15, X15)
	PADDL X0, X7
	PADDL X1, X8
	PADDL X2, X9
	XOR64(AX, BX, 64, X7, X8, X9, X10, X15, X3)
	PADDL X0, X11
	PADDL X1, X12
	PADDL X2, X13
	XOR64(AX, BX, 128, X11, X12, X13, X14, X15, X3)
	ADDL $1, DI
	MOVL DI, 48(CX)
	ADDQ $192, AX
	ADDQ $192, BX
	SUBQ $192, DX
	JNE xor_loop
	RET
	