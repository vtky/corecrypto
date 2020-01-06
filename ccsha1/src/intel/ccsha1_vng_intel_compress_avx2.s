# Copyright (c) 2016,2018 Apple Inc. All rights reserved.
#
# corecrypto Internal Use License Agreement
#
# IMPORTANT:  This Apple corecrypto software is supplied to you by Apple Inc. ("Apple")
# in consideration of your agreement to the following terms, and your download or use
# of this Apple software constitutes acceptance of these terms.  If you do not agree
# with these terms, please do not download or use this Apple software.
#
# 1.    As used in this Agreement, the term "Apple Software" collectively means and
# includes all of the Apple corecrypto materials provided by Apple here, including
# but not limited to the Apple corecrypto software, frameworks, libraries, documentation
# and other Apple-created materials. In consideration of your agreement to abide by the
# following terms, conditioned upon your compliance with these terms and subject to
# these terms, Apple grants you, for a period of ninety (90) days from the date you
# download the Apple Software, a limited, non-exclusive, non-sublicensable license
# under Apple’s copyrights in the Apple Software to make a reasonable number of copies
# of, compile, and run the Apple Software internally within your organization only on
# devices and computers you own or control, for the sole purpose of verifying the
# security characteristics and correct functioning of the Apple Software; provided
# that you must retain this notice and the following text and disclaimers in all
# copies of the Apple Software that you make. You may not, directly or indirectly,
# redistribute the Apple Software or any portions thereof. The Apple Software is only
# licensed and intended for use as expressly stated above and may not be used for other
# purposes or in other contexts without Apple's prior written permission.  Except as
# expressly stated in this notice, no other rights or licenses, express or implied, are
# granted by Apple herein.
#
# 2.    The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
# WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED WARRANTIES
# OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, REGARDING
# THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS,
# SYSTEMS, OR SERVICES. APPLE DOES NOT WARRANT THAT THE APPLE SOFTWARE WILL MEET YOUR
# REQUIREMENTS, THAT THE OPERATION OF THE APPLE SOFTWARE WILL BE UNINTERRUPTED OR
# ERROR-FREE, THAT DEFECTS IN THE APPLE SOFTWARE WILL BE CORRECTED, OR THAT THE APPLE
# SOFTWARE WILL BE COMPATIBLE WITH FUTURE APPLE PRODUCTS, SOFTWARE OR SERVICES. NO ORAL
# OR WRITTEN INFORMATION OR ADVICE GIVEN BY APPLE OR AN APPLE AUTHORIZED REPRESENTATIVE
# WILL CREATE A WARRANTY.
#
# 3.    IN NO EVENT SHALL APPLE BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT, INCIDENTAL
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
# GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) ARISING
# IN ANY WAY OUT OF THE USE, REPRODUCTION, COMPILATION OR OPERATION OF THE APPLE
# SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING
# NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
# 4.    This Agreement is effective until terminated. Your rights under this Agreement will
# terminate automatically without notice from Apple if you fail to comply with any term(s)
# of this Agreement.  Upon termination, you agree to cease all use of the Apple Software
# and destroy all copies, full or partial, of the Apple Software. This Agreement will be
# governed and construed in accordance with the laws of the State of California, without
# regard to its choice of law rules.
#
# You may report security issues about Apple products to product-security@apple.com,
# as described here:  https://www.apple.com/support/security/.  Non-security bugs and
# enhancement requests can be made via https://bugreport.apple.com as described
# here: https://developer.apple.com/bug-reporting/
#
# EA1350
# 10/5/15

#include <corecrypto/cc_config.h>

#if CCSHA1_VNG_INTEL

/* 	vng_sha1LittleEndian.s : this file provides optimized x86_64 avx2 implementation of the sha1 function
	CoreOS - vector and numerics group

	The implementation is based on the principle described in an Intel online article
	"Improving the Performance of the Secure Hash Algorithm (SHA-1)"
	http://software.intel.com/en-us/articles/improving-the-performance-of-the-secure-hash-algorithm-1/


	Update HASH[] by processing a one 64-byte block in MESSAGE[] can be represented by the following C function

void SHA1( int HASH[], int MESSAGE[] )
{
    int A[81], B[81], C[81], D[81], E[81];
    int W[80];

    int i, FN;

    A[0] = HASH[0];
    B[0] = HASH[1];
    C[0] = HASH[2];
    D[0] = HASH[3];
    E[0] = HASH[4];

    for ( i=0; i<80; ++i )
    {
        if ( i < 16 )
            W[i] = BIG_ENDIAN_LOAD( MESSAGE[i] );
        else
            W[i] = ROTATE_LEFT( W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1 );

        FN = F( i, B[i], C[i], D[i] );

        A[i+1] = FN + E[i] + ROTATE_LEFT( A[i], 5 ) + W[i] + K(i);
        B[i+1] = A[i];
        C[i+1] = ROTATE_LEFT( B[i], 30 );
        D[i+1] = C[i];
        E[i+1] = D[i];
    }

    HASH[0] += A[80];
    HASH[1] += B[80];
    HASH[2] += C[80];
    HASH[3] += D[80];
    HASH[4] += E[80];
}

	For i=0:15, W[i] is simply big-endian loading of MESSAGE[i]. For i=16:79, W[i] is updated according to W[i] = ROTATE_LEFT( W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16], 1 );

	The approach (by Dean Gaudet) can be used to vectorize the computation of W[i] for i=16:79,

	1. done on 4 consequtive W[i] values in a single XMM register
    W[i  ] = (W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]) rol 1
    W[i+1] = (W[i-2] ^ W[i-7] ^ W[i-13] ^ W[i-15]) rol 1
    W[i+2] = (W[i-1] ^ W[i-6] ^ W[i-12] ^ W[i-14]) rol 1
    W[i+3] = (   0   ^ W[i-5] ^ W[i-11] ^ W[i-13]) rol 1

    2. this additional calculation unfortunately requires many additional operations
    W[i+3] ^= W[i] rol 1

    3. once we have 4 W[i] values in XMM we can also add four K values with one instruction
    W[i:i+3] += {K,K,K,K}

	Let W0 = {W[i] W[i+1] W[i+2] W[i+3]} be the current W-vector to be computed, W4 = {W[i-4] W[i-3] W[i-2] W[i-1]} be the previous vector, and so on
	The Dean Gaudet approach can be expressed as

	1. W0 = rotate_left(left_shift(W4,32) ^ W8 ^ left_shift(concatenate(W16,W12),64) ^ W16,1);
	2. W[i+3] ^= W[i] rol 1
	3. W0 += {K,K,K,K}

	For i>=32, the Intel online article suggests that (using a basic identity (X rol 1) rol 1 = X rol 2) the update equation is equivalent to

	1. W0 = rotate_left(left_shift(concatenate(W8,W4),64) ^ W16 ^ W28 ^ W32, 2);

	Note:
	1. In total, we need 8 16-byte registers or memory for W0,W4,...,W28. W0 and W32 can be the same register or memory.
	2. The registers are used in a circular buffering mode. For example, we start with W28,W24,...,W0 (with W0 indicating the most recent 16-byte)
		i=0, W28,W24,...,W0
		i=4, W24,W20,...,W28
		i=8, W20,W16,...,W24
		.
		.
		and so forth.
	3. 2 ssse3 instructions are used in the Intel article, pshufb and palignr.
		a. pshufb is used to simplify the BIG_ENDIAN_LOAD operation
		b. palignr is used to simplify the computation of left_shift(concatenate(W12,W8),64)

*/

/* the code can be compiled into single block (64 bytes) per call mode by setting Multiple_blocks to 0 */
#define	Multiple_Blocks	1

#if defined (__x86_64__)

#if CC_KERNEL
#define	stack_size	(32*10+16*4+16)					// ymm0-9 + 4 128-bits for intermediate WK(t) storage + 32byte alignment
#else
#define	stack_size	(16*4)		        			// 4 128-bits for intermediate WK(t) storage
#endif
#define	sp			%rsp							// unifying architectural stack pointer representation
#define	ctx			%rdi							// 1st input argument, will move to HASH_PTR (%r9)
#define	buf			%rdx							// 3rd input argument, will move to BUFFER_PTR (%r10)
#define	cnt         %r11							// will copy from the 2nd input argument (%rsi)
#define K_BASE		%r8								// an aligned pointer to point to shufb reference numbers of table of K values
#define HASH_PTR	%r9								// pointer to Hash values (A,B,C,D,E)
#define BUFFER_PTR  %r10							// pointer to input blocks

// symbolizing registers or stack memory with algorithmic variables	W0,W4,...,W28 + W_TMP, W_TMP2, and XMM_SHUFB_BSWAP for code with avx2 support

#define W_TMP  	%xmm0
#define W_TMP2 	%xmm1
#define W0  	%xmm2
#define W4  	%xmm3
#define W8  	%xmm4
#define W12 	%xmm5
#define W16 	%xmm6
#define W20 	%xmm7
#define W24 	%xmm8
#define W28 	%xmm9
#define XMM_SHUFB_BSWAP REV32(%rip)

#define	xmov	vmovaps						// aligned 16-byte move
#define	xmovu	vmovups						// unaligned 16-byte move

// intermediate hash variables
#define A %ecx
#define B %esi
#define C %edi
#define D %r15d
#define E %edx

// temp variables
#define T1 %eax
#define T2 %ebx

#define	WK(t)	(t&15)*4(sp)

	// int F1(int B, int C, int D) { return (D ^ ( B & (C ^ D)); }
	// result in T1
	.macro	F1
	mov	$1, T1
	xor	$2, T1
	and	$0, T1
	xor	$2, T1
	.endm

	// int F2(int B, int C, int D) { return (D ^ B ^ C); }
	// result in T1
	.macro	F2
	mov	$2, T1
	xor	$1, T1
	xor	$0, T1
	.endm

	// int F3(int B, int C, int D) { return (B & C) | (D & (B ^ C)); }
	// result in T1
	.macro	F3
		mov $1, T1
        mov $0, T2
        or  $0, T1
        and $1, T2
        and $2, T1
        or  T2, T1
	.endm

	// for i=60:79, F4 is identical to F2
	#define	F4	F2


	/*
		i=0:15, W[i] = BIG_ENDIAN_LOAD(MESSAGE[i]);

		for (i=0;i<16;i+=4) {
			1. W_TMP = new 16 bytes from MESSAGE[]
			2. W_TMP = pshufb(W_TMP, XMM_SHUFB_BSWAP); save to W circular buffer for updating W
			3. WTMP += {K,K,K,K};
			4. save quadruple W[i]+K[i] = W_TMP in the stack memory;
		}

		each step is represented in one of the following 4 macro definitions

	*/

	.macro	W_PRECALC_00_15_0   			// input argument $0 : 0/4/8/12
	xmovu	$0*4(BUFFER_PTR), W_TMP			// read 16-bytes into W_TMP, BUFFER_PTR possibly not 16-byte aligned
	.endm

	.macro	W_PRECALC_00_15_1   			// input argument $0 : current 16-bytes in the circular buffer, one of W0,W4,W8,...,W28
	vpshufb	XMM_SHUFB_BSWAP, W_TMP, $0		// convert W_TMP from little-endian into big-endian
	.endm

	.macro	W_PRECALC_00_15_2				// K_BASE points to the current K quadruple.
	vpaddd	(K_BASE), $0, W_TMP					// W_TMP += {K,K,K,K};
	.endm

	.macro	W_PRECALC_00_15_3
	xmov	W_TMP, WK($0&~3)				// save quadruple W[i]+K in the stack memory, which would be used later for updating the hashes A/B/C/D/E
	.endm

	// rounds 16-31 compute W[0] using the vectorization approach by Dean Gaudet
	/*
	W[i  ] = (W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]) rol 1
    W[i+1] = (W[i-2] ^ W[i-7] ^ W[i-13] ^ W[i-15]) rol 1
    W[i+2] = (W[i-1] ^ W[i-6] ^ W[i-12] ^ W[i-14]) rol 1
    W[i+3] = (   0   ^ W[i-5] ^ W[i-11] ^ W[i-13]) rol 1

	W[i+3] ^= W[i] rol 1;	// this W[i] is already rol by 1, if we are taking from the intial W before rol 1, we should rol this by 2

	The operation (updating W and W+K) is scheduled as and divided into 4 steps

	0. W_tmp = W3; W = W14 ^ W8
	1. W = W3 ^ W8 ^ W14 ^ W16; W_TMP = W; W_TMP2 = (W[i] 0 0 0);
	2. W_TMP = (W3 ^ W8 ^ W14 ^ W16) rol 1; split (W[i] 0 0 0) rol 2 in W_TMP2 and W
	3. W = W_TMP = W_TMP ^ W_TMP2 ^ W = (W3 ^ W8 ^ W14 ^ W16) rol 1 ^ (W[i] 0 0 0) rol 2; WK = W _TMP+K;

	*/

	.macro	W_PRECALC_16_31_0   	// input arguments : W16,W12,W8,W4,W
	vpalignr	$$8, $0, $1, $4		// W = W14
	vpsrldq	    $$4, $3, W_TMP		// W_TMP = W3
	vpxor	    $2, $4, $4			// W = W8 ^ W14
	.endm

	.macro	W_PRECALC_16_31_1		// input arguments : W16,W
	vpxor	$0, W_TMP, W_TMP		// W_TMP = W3 ^ W16
	vpxor	W_TMP, $1, $1			// W = W3 ^ W16 ^ W8 ^ W14
	vpslldq	$$12, $1, W_TMP2			// W_TMP2 = (W[i] 0 0 0)
	.endm

	.macro	W_PRECALC_16_31_2		// input argument : W
	vpslld	$$1, $0, W_TMP			// (W3 ^ W16 ^ W8 ^ W14)<<1
	vpsrld	$$31, $0, $0			// (W3 ^ W16 ^ W8 ^ W14)>>31
	vpor	$0, W_TMP, W_TMP		// W_TMP = (W3 ^ W16 ^ W8 ^ W14) rol 1
	vpslld	$$2, W_TMP2, $0			// W = W[i] higher 30 bits after rol 2
	vpsrld	$$30, W_TMP2, W_TMP2	// W_TMP2 = W[i] lower 2 bits after rol 2
	.endm

	.macro	W_PRECALC_16_31_3		// input arguments: W, i, K_XMM
	vpxor	W_TMP, $0, $0
	vpxor	W_TMP2, $0, $0			// W_TMP = (W3 ^ W16 ^ W8 ^ W14) rol 1 ^ (W[i] 0 0 0) rol 2
	vpaddd	$2(K_BASE), $0, W_TMP	// W+K
	xmov	W_TMP, WK($1&~3)		// save WK = W+K for later update of the hashes A/B/C/D/E
	.endm

	/* rounds 32-79 compute W und W+K iusing the vectorization approach from the Intel article

		W = rotate_left(left_shift(concatenate(W8,W4),64) ^ W16 ^ W28 ^ W32, 2);

		where left_shift(concatenate(W8,W4),64) is equivalent to W6. Note also that W32 and W use the same register.


	0. W_tmp = W6; W = W28 ^ W32;
	1. W = W_tmp = W6 ^ W16 ^ W28 ^ W32;
	2. W_tmp = (W6 ^ W16 ^ W28 ^ W32) rol 2;
	3. W = W_Tmp; WK = W_tmp + K;

	*/


	.macro	W_PRECALC_32_79_0   		// inputr arguments : W28,W8,W4,W
	vpxor	    $0, $3, $3				// W = W28 ^ W32;
	vpalignr	$$8, $1, $2, W_TMP		// W_tmp = (w3 w4 w5 w6) = W6;
	.endm

	.macro	W_PRECALC_32_79_1			// input arguments : W16,W
	vpxor	$0, $1, $1					// W_tmp = W6 ^ W16
	vpxor	W_TMP, $1, $1				// W_tmp = W6 ^ W16 ^ W28 ^ W32
	//xmov	W_TMP, $1					// W = W_tmp = W6 ^ W16 ^ W28 ^ W32
	.endm

	.macro	W_PRECALC_32_79_2			// input argument : W
	vpslld	$$2, $0, W_TMP				// W << 2
	vpsrld	$$30, $0, $0				// W >> 30
	vpor	W_TMP, $0, $0				// W_tmp = (W6 ^ W16 ^ W28 ^ W32) rol 2
	.endm

	.macro	W_PRECALC_32_79_3			// input argument W, i, K_XMM
	vpaddd	$2(K_BASE), $0, W_TMP		// W + K
	xmov	W_TMP, WK($1&~3)			// write W+K
	.endm


	/* The hash update operation is completed by the following statements.

		A[i+1] = FN + E[i] + ROTATE_LEFT( A[i], 5 ) + WK(i);
        B[i+1] = A[i];
        C[i+1] = ROTATE_LEFT( B[i], 30 );
        D[i+1] = C[i];
        E[i+1] = D[i];

		Suppose we start with A0,B0,C0,D0,E0. The 1st iteration can be expressed as follows:

		A1 = FN + E0 + rol(A0,5) + WK;
		B1 = A0;
		C1 = rol(B0, 30);
		D1 = C0;
		E1 = D0;

		to avoid excessive memory movement between registers,
			1. A1 = FN + E0 + rol(A0,5) + WK; can be temporarily saved in E0,
			2. C1 = rol(B0,30) can be temporarily saved in B0.

		Therefore, ignoring the time index, the update operation is equivalent to
			1. E = FN(B,C,D) + E + rol(A,5) + WK(i)
			2. B = rol(B,30)
			3. the hashes are now stored in the order of E,A,B,C,D


		To pack 2 hash update operations in 1 iteration, starting with A,B,C,D,E
		1. E = FN(B,C,D) + E + rol(A,5) + WK(i)
		2. B = rol(B,30)
		// now the hashes are in the order of E,A,B,C,D
		3. D = FN(A,B,C) + D + rol(E,5) + WK(i+1)
		4. A = rol(A,30)
		// now the hashes are in the order of D,E,A,B,C

		These operations are distributed into the following 2 macro definitions RR0 and RR1.

	*/

	.macro	RR0				// input arguments : FN, A, B, C, D, E, i
	$0		$2, $3, $4		// T1 = FN(B,C,D)
	rol		$$30, $2		// B = rol(B,30)
	add		WK($6), $5		// E + WK(i)
	rorx	$$27, $1, T2    // rol(A,5)
	add		WK($6+1), $4	// D + WK(i+1)
	add		T1, $5			// E = FN(B,C,D) + E + WK(i)
	.endm

	.macro	RR1
	add		T2, $5			// T2 = FN(B,C,D) + E + rol(A,5) + WK(i)
	rorx	$$27, $5, T2	// rol(E,5)
	add		T2, $4			// D + WK(i+1) + rol(E,5)
	$0		$1, $2, $3		// FN(A,B,C)
	add		T1, $4			// D = FN(A,B,C) + D + rol(E,5) + WK(i+1)
	rol		$$30, $1		// A = rol(A,30)
	.endm


	.macro	INITIAL_W_PRECALC   			// BIG_ENDIAN_LOAD(64 bytes block) into W (i=0:15) and store W+K into the stack memory

	// i=0 	: W28,W24,W20,W16,W12,W8,W4,W0
	W_PRECALC_00_15_0	0					// W_TMP = (BUFFER_PTR)
	W_PRECALC_00_15_1	W0					// convert W_TMP to big-endian, and save W0 = W_TMP
	W_PRECALC_00_15_2   W0  				// W_TMP = W0 + K
	W_PRECALC_00_15_3	3					// (sp) = W_TMP = W0 + K

	// i=4	: W24,W20,W16,W12,W8,W4,W0,W28
	W_PRECALC_00_15_0	4					// W_TMP = 16(BUFFER_PTR)
	W_PRECALC_00_15_1	W28					// convert W_TMP to big-endian, and save W28 = W_TMP
	W_PRECALC_00_15_2   W28					// W_TMP = W28 + K
	W_PRECALC_00_15_3	7					// 16(sp) = W_TMP = W28 + K

	// i=8  : W20,W16,W12,W8,W4,W0,W28,W24
	W_PRECALC_00_15_0	8					// W_TMP = 32(BUFFER_PTR)
	W_PRECALC_00_15_1	W24					// convert W_TMP to big-endian, and save W24 = W_TMP
	W_PRECALC_00_15_2   W24					// W_TMP = W24 + K
	W_PRECALC_00_15_3	11					// 32(sp) = W_TMP = W24 + K

	// i=12 : W16,W12,W8,W4,W0,W28,W24,W20
	W_PRECALC_00_15_0	12					// W_TMP = 48(BUFFER_PTR)
	W_PRECALC_00_15_1	W20					// convert W_TMP to big-endian, and save W20 = W_TMP
	W_PRECALC_00_15_2   W20					// W_TMP = W20 + K
	W_PRECALC_00_15_3	15					// 48(sp) = W_TMP = W20 + K

	.endm


	.macro	INTERNAL    					// updating W (16:79) and update the digests A/B/C/D/E (i=0:63, based on W+K stored in the stack memory)

	// i=16 : W12,W8,W4,W0,W28,W24,W20,W16
	W_PRECALC_16_31_0	W0,W28,W24,W20,W16
	RR0					F1,A,B,C,D,E,0
	W_PRECALC_16_31_1	W0,W16
	RR1					F1,A,B,C,D,E,0
	W_PRECALC_16_31_2	W16
	RR0					F1,D,E,A,B,C,2
	W_PRECALC_16_31_3	W16, 2, 0
	RR1					F1,D,E,A,B,C,2

	// i=20 : W8,W4,W0,W28,W24,W20,W16,W12
	W_PRECALC_16_31_0	W28,W24,W20,W16,W12
	RR0					F1,B,C,D,E,A,4
	W_PRECALC_16_31_1	W28,W12
	RR1					F1,B,C,D,E,A,4
	W_PRECALC_16_31_2	W12
	RR0					F1,E,A,B,C,D,6
	W_PRECALC_16_31_3	W12, 6, 16
	RR1					F1,E,A,B,C,D,6

	// i=24 : W4,W0,W28,W24,W20,W16,W12,W8
	W_PRECALC_16_31_0	W24,W20,W16,W12,W8
	RR0					F1,C,D,E,A,B,8
	W_PRECALC_16_31_1	W24,W8
	RR1					F1,C,D,E,A,B,8
	W_PRECALC_16_31_2	W8
	RR0					F1,A,B,C,D,E,10
	W_PRECALC_16_31_3	W8,10,16
	RR1					F1,A,B,C,D,E,10

	// i=28 : W0,W28,W24,W20,W16,W12,W8,W4
	W_PRECALC_16_31_0	W20,W16,W12,W8,W4
	RR0					F1,D,E,A,B,C,12
	W_PRECALC_16_31_1	W20,W4
	RR1					F1,D,E,A,B,C,12
	W_PRECALC_16_31_2	W4
	RR0					F1,B,C,D,E,A,14
	W_PRECALC_16_31_3	W4,14,16
	RR1					F1,B,C,D,E,A,14

	// i=32 : W28,W24,W20,W16,W12,W8,W4,W0
	W_PRECALC_32_79_0	W28,W8,W4,W0
	RR0					F1,E,A,B,C,D,16
	W_PRECALC_32_79_1	W16,W0
	RR1					F1,E,A,B,C,D,16
	W_PRECALC_32_79_2	W0
	RR0					F1,C,D,E,A,B,18
	W_PRECALC_32_79_3	W0,18,16
	RR1					F1,C,D,E,A,B,18

	// starting using F2

	// i=36 : W24,W20,W16,W12,W8,W4,W0,W28
	W_PRECALC_32_79_0	W24,W4,W0,W28
	RR0					F2,A,B,C,D,E,20
	W_PRECALC_32_79_1	W12,W28
	RR1					F2,A,B,C,D,E,20
	W_PRECALC_32_79_2	W28
	RR0					F2,D,E,A,B,C,22
	W_PRECALC_32_79_3	W28,22,16
	RR1					F2,D,E,A,B,C,22

	// i=40 : W20,W16,W12,W8,W4,W0,W28,W24
	#undef  K_XMM
    #define K_XMM   32
	W_PRECALC_32_79_0	W20,W0,W28,W24
	RR0					F2,B,C,D,E,A,24
	W_PRECALC_32_79_1	W8,W24
	RR1					F2,B,C,D,E,A,24
	W_PRECALC_32_79_2	W24
	RR0					F2,E,A,B,C,D,26
	W_PRECALC_32_79_3	W24,26,K_XMM
	RR1					F2,E,A,B,C,D,26

	// i=44 : W16,W12,W8,W4,W0,W28,W24,W20
	W_PRECALC_32_79_0	W16,W28,W24,W20
	RR0					F2,C,D,E,A,B,28
	W_PRECALC_32_79_1	W4,W20
	RR1					F2,C,D,E,A,B,28
	W_PRECALC_32_79_2	W20
	RR0					F2,A,B,C,D,E,30
	W_PRECALC_32_79_3	W20,30,K_XMM
	RR1					F2,A,B,C,D,E,30

	// i=48 : W12,W8,W4,W0,W28,W24,W20,W16
	W_PRECALC_32_79_0	W12,W24,W20,W16
	RR0					F2,D,E,A,B,C,32
	W_PRECALC_32_79_1	W0,W16
	RR1					F2,D,E,A,B,C,32
	W_PRECALC_32_79_2	W16
	RR0					F2,B,C,D,E,A,34
	W_PRECALC_32_79_3	W16,34,K_XMM
	RR1					F2,B,C,D,E,A,34

	// i=52 : W8,W4,W0,W28,W24,W20,W16,W12
	W_PRECALC_32_79_0	W8,W20,W16,W12
	RR0					F2,E,A,B,C,D,36
	W_PRECALC_32_79_1	W28,W12
	RR1					F2,E,A,B,C,D,36
	W_PRECALC_32_79_2	W12
	RR0					F2,C,D,E,A,B,38
	W_PRECALC_32_79_3	W12,38,K_XMM
	RR1					F2,C,D,E,A,B,38

	// starting using F3

	// i=56 : W4,W0,W28,W24,W20,W16,W12,W8
	W_PRECALC_32_79_0	W4,W16,W12,W8
	RR0					F3,A,B,C,D,E,40
	W_PRECALC_32_79_1	W24,W8
	RR1					F3,A,B,C,D,E,40
	W_PRECALC_32_79_2	W8
	RR0					F3,D,E,A,B,C,42
	W_PRECALC_32_79_3	W8,42,K_XMM
	RR1					F3,D,E,A,B,C,42

	// i=60 : W0,W28,W24,W20,W16,W12,W8,W4
	#undef	K_XMM
	#define	K_XMM	48
	W_PRECALC_32_79_0	W0,W12,W8,W4
	RR0					F3,B,C,D,E,A,44
	W_PRECALC_32_79_1	W20,W4
	RR1					F3,B,C,D,E,A,44
	W_PRECALC_32_79_2	W4
	RR0					F3,E,A,B,C,D,46
	W_PRECALC_32_79_3	W4,46,K_XMM
	RR1					F3,E,A,B,C,D,46

	// i=64 : W28,W24,W20,W16,W12,W8,W4,W0
	W_PRECALC_32_79_0	W28,W8,W4,W0
	RR0					F3,C,D,E,A,B,48
	W_PRECALC_32_79_1	W16,W0
	RR1					F3,C,D,E,A,B,48
	W_PRECALC_32_79_2	W0
	RR0					F3,A,B,C,D,E,50
	W_PRECALC_32_79_3	W0,50,K_XMM
	RR1					F3,A,B,C,D,E,50

	// i=68 : W24,W20,W16,W12,W8,W4,W0,W28
	W_PRECALC_32_79_0	W24,W4,W0,W28
	RR0					F3,D,E,A,B,C,52
	W_PRECALC_32_79_1	W12,W28
	RR1					F3,D,E,A,B,C,52
	W_PRECALC_32_79_2	W28
	RR0					F3,B,C,D,E,A,54
	W_PRECALC_32_79_3	W28,54,K_XMM
	RR1					F3,B,C,D,E,A,54

	// i=72 : W20,W16,W12,W8,W4,W0,W28,W24
	W_PRECALC_32_79_0	W20,W0,W28,W24
	RR0					F3,E,A,B,C,D,56
	W_PRECALC_32_79_1	W8,W24
	RR1					F3,E,A,B,C,D,56
	W_PRECALC_32_79_2	W24
	RR0					F3,C,D,E,A,B,58
	W_PRECALC_32_79_3	W24,58,K_XMM
	RR1					F3,C,D,E,A,B,58

	// starting using F4

	// i=76 : W16,W12,W8,W4,W0,W28,W24,W20
	W_PRECALC_32_79_0	W16,W28,W24,W20
	RR0					F4,A,B,C,D,E,60
	W_PRECALC_32_79_1	W4,W20
	RR1					F4,A,B,C,D,E,60
	W_PRECALC_32_79_2	W20
	RR0					F4,D,E,A,B,C,62
	W_PRECALC_32_79_3	W20,62,K_XMM
	RR1					F4,D,E,A,B,C,62

	.endm

	.macro	SOFTWARE_PIPELINING
	// i=0  : W28,W24,W20,W16,W12,W8,W4,W0
	W_PRECALC_00_15_0	0					// W_TMP = (BUFFER_PTR)
	RR0					F4,B,C,D,E,A,64
	W_PRECALC_00_15_1	W0					// convert W_TMP to big-endian, and save W0 = W_TMP
	RR1					F4,B,C,D,E,A,64
	W_PRECALC_00_15_2   W0					// W_TMP = W0 + K
	RR0					F4,E,A,B,C,D,66
	W_PRECALC_00_15_3	3					// (sp) = W_TMP = W0 + K
	RR1					F4,E,A,B,C,D,66

	// i=4  : W24,W20,W16,W12,W8,W4,W0,W28
	W_PRECALC_00_15_0	4					// W_TMP = 16(BUFFER_PTR)
	RR0					F4,C,D,E,A,B,68
	W_PRECALC_00_15_1	W28					// convert W_TMP to big-endian, and save W28 = W_TMP
	RR1					F4,C,D,E,A,B,68
	W_PRECALC_00_15_2   W28					// W_TMP = W28 + K
	RR0					F4,A,B,C,D,E,70
	W_PRECALC_00_15_3	7					// 16(sp) = W_TMP = W28 + K[0]
	RR1					F4,A,B,C,D,E,70

	// i=8  : W20,W16,W12,W8,W4,W0,W28,W24
	W_PRECALC_00_15_0	8					// W_TMP = 32(BUFFER_PTR)
	RR0					F4,D,E,A,B,C,72
	W_PRECALC_00_15_1	W24					// convert W_TMP to big-endian, and save W24 = W_TMP
	RR1					F4,D,E,A,B,C,72
	W_PRECALC_00_15_2	W24					// W_TMP = W24 + K
	RR0					F4,B,C,D,E,A,74
	W_PRECALC_00_15_3	11					// 32(sp) = W_TMP = W24 + K
	RR1					F4,B,C,D,E,A,74

	// i=12 : W16,W12,W8,W4,W0,W28,W24,W20
	W_PRECALC_00_15_0	12					// W_TMP = 48(BUFFER_PTR)
	RR0					F4,E,A,B,C,D,76
	W_PRECALC_00_15_1	W20					// convert W_TMP to big-endian, and save W20 = W_TMP
	RR1					F4,E,A,B,C,D,76
	W_PRECALC_00_15_2	W20					// W_TMP = W20 + K
	RR0					F4,C,D,E,A,B,78
	W_PRECALC_00_15_3	15					// 48(sp) = W_TMP = W20 + K
	RR1					F4,C,D,E,A,B,78
	.endm


	#undef	W_PRECALC_00_15_0
	#undef	W_PRECALC_00_15_1
	#undef	W_PRECALC_16_31_0
	#undef	W_PRECALC_32_79_0

	.macro	ENDING		// finish up updating hash digests (i=64:79)
	//i=80
	RR0					F4,B,C,D,E,A,64
	RR1					F4,B,C,D,E,A,64
	RR0					F4,E,A,B,C,D,66
	RR1					F4,E,A,B,C,D,66

	//i=84
	RR0					F4,C,D,E,A,B,68
	RR1					F4,C,D,E,A,B,68
	RR0					F4,A,B,C,D,E,70
	RR1					F4,A,B,C,D,E,70

	//i=88
	RR0					F4,D,E,A,B,C,72
	RR1					F4,D,E,A,B,C,72
	RR0					F4,B,C,D,E,A,74
	RR1					F4,B,C,D,E,A,74

	//i=92
	RR0					F4,E,A,B,C,D,76
	RR1					F4,E,A,B,C,D,76
	RR0					F4,C,D,E,A,B,78
	RR1					F4,C,D,E,A,B,78
	.endm

	// load hash digests A,B,C,D,E from memory into registers
	.macro	LOAD_HASH
	mov			(HASH_PTR), A
	mov			4(HASH_PTR), B
	mov			8(HASH_PTR), C
	mov			12(HASH_PTR), D
	mov			16(HASH_PTR), E
	.endm

	.macro	UPDATE_HASH
	add		$0, $1
	mov		$1, $0
	.endm

	.macro UPDATE_ALL_HASH
	UPDATE_HASH		(HASH_PTR), A
	UPDATE_HASH		4(HASH_PTR), B
	UPDATE_HASH		8(HASH_PTR), C
	UPDATE_HASH		12(HASH_PTR), D
	UPDATE_HASH		16(HASH_PTR), E
	.endm


	/*
		 main sha1 code for system with avx2 support
	*/

	.macro  SHA1_PIPELINED_MAIN_BODY
	LOAD_HASH						// load initial hashes into A,B,C,D,E
	INITIAL_W_PRECALC   			// big_endian_load(W) and W+K (i=0:15)
	.align	4,0x90
0:
	INTERNAL    					// update W (i=16:79) and update ABCDE (i=0:63)
#if Multiple_Blocks
	addq	$$64, BUFFER_PTR			// BUFFER_PTR+=64;
	subq	$$1, cnt					// pre-decrement cnt by 1
	jbe	1f							// if cnt <= 0, branch to finish off
	SOFTWARE_PIPELINING     		// update ABCDE (i=64:79) || big_endian_load(W) and W+K (i=0:15)
	UPDATE_ALL_HASH					// update output hashes
	jmp	0b							// repeat for next block
	.align	4,0x90
1:
#endif
	ENDING							// update ABCDE (i=64:79)
	UPDATE_ALL_HASH					// update output hashes
	.endm

/*
	I removed the cpu capabilities check.  The check is now down
	in C code and the appropriate version of the assembler code
	is selected.
*/
	.text
	.globl _ccsha1_vng_intel_compress_AVX2
	.private_extern _ccsha1_vng_intel_compress_AVX2
_ccsha1_vng_intel_compress_AVX2:

	// start the sha1 code with avx2 support

	// save callee-save registers
	push	%rbp
    mov     %rsp, %rbp
	push	%rbx
	push	%r15

	sub		$stack_size, sp					// allocate stack memory for use

	// save used xmm register if this is for kernel
#if CC_KERNEL
    andq    $-32, sp                        // aligned sp to 32-bytes
    leaq    4*16(sp), %rax
    xmov    %ymm0, 0*32(%rax)
    xmov    %ymm1, 1*32(%rax)
    xmov    %ymm2, 2*32(%rax)
    xmov    %ymm3, 3*32(%rax)
    xmov    %ymm4, 4*32(%rax)
    xmov    %ymm5, 5*32(%rax)
    xmov    %ymm6, 6*32(%rax)
    xmov    %ymm7, 7*32(%rax)
    xmov    %ymm8, 8*32(%rax)
    xmov    %ymm9, 9*32(%rax)
#endif


	// set up registers to free %edx/%edi/%esi for other use (ABCDE)
	mov		ctx, HASH_PTR
	mov		buf, BUFFER_PTR
#if Multiple_Blocks
	mov		%rsi, cnt
#endif
	lea		K_XMM_AR(%rip), K_BASE


	SHA1_PIPELINED_MAIN_BODY

	// restore used xmm registers if this is for kernel
#if CC_KERNEL
    leaq    4*16(sp), %rax
    xmov    0*32(%rax), %ymm0
    xmov    1*32(%rax), %ymm1
    xmov    2*32(%rax), %ymm2
    xmov    3*32(%rax), %ymm3
    xmov    4*32(%rax), %ymm4
    xmov    5*32(%rax), %ymm5
    xmov    6*32(%rax), %ymm6
    xmov    7*32(%rax), %ymm7
    xmov    8*32(%rax), %ymm8
    xmov    9*32(%rax), %ymm9
#endif

	leaq    	-16(%rbp), %rsp

	// restore callee-save registers
	pop		%r15
	pop		%rbx
	pop		%rbp

	ret							// return

	.const
	.align	4, 0x90

#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6

K_XMM_AR:
    .long	K1
	.long	K1
	.long	K1
	.long	K1
    .long	K2
	.long	K2
	.long	K2
	.long	K2
    .long	K3
	.long	K3
	.long	K3
	.long	K3
    .long	K4
	.long	K4
	.long	K4
	.long	K4
REV32:
// bswap_shufb_ctl: accessed thru 0x40(K_XMM_AR)
    .long	0x00010203
    .long	0x04050607
    .long	0x08090a0b
    .long	0x0c0d0e0f


#endif	// architecture x86_64

#endif /* CCSHA1_VNG_INTEL */

