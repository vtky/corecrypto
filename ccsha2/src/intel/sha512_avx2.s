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

#if CCSHA2_VNG_INTEL

/*
	This file provides x86_64 avx2 hand implementation of the following function

    void ccsha512_compress(uint64_t *state, size_t nblocks, const void *in);

	sha512 algorithm per block description:

		1. W(0:15) = big-endian (per 8 bytes) loading of input data (128 bytes)
		2. load 8 digests (each 64bit) a-h from state
		3. for r = 0:15
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g
		4. for r = 16:79
				W[r] = W[r-16] + Gamma1(W[r-2]) + W[r-7] + Gamma0(W[r-15]);
				T1 = h + Sigma1(e) + Ch(e,f,g) + K[r] + W[r];
				d += T1;
				h = T1 + Sigma0(a) + Maj(a,b,c)
				permute a,b,c,d,e,f,g,h into h,a,b,c,d,e,f,g

	In the assembly implementation:
		- a circular window of message schedule W(r:r+15) is updated and stored in xmm0-xmm7 (or ymm0-ymm3/zmm0-zmm1 for avx2/avx512)
		- its corresponding W+K(r:r+15) is updated and stored in a stack space circular buffer
		- the 8 digests (a-h) will be stored in GPR (%r8-%r15) 

	----------------------------------------------------------------------------

	our implementation (allows multiple blocks per call) pipelines the loading of W/WK of a future block
	into the last 16 rounds of its previous block:

	----------------------------------------------------------------------------

	load W(0:15) (big-endian per 8 bytes) into xmm0:xmm7
	pre_calculate and store W+K(0:15) in stack

L_loop:

	load digests a-h from ctx->state;

	for (r=0;r<64;r+=2) {
		digests a-h update and permute round r:r+1
		update W([r:r+1]%16) and WK([r:r+1]%16) for the next 8th iteration
	}

	num_block--;
	if (num_block==0)	jmp L_last_block;

	for (r=64;r<80;r+=2) {
		digests a-h update and permute round r:r+1
		load W([r:r+1]%16) (big-endian per 8 bytes) into xmm0:xmm7
		pre_calculate and store W+K([r:r+1]%16) in stack
	}

	ctx->states += digests a-h;

	jmp	L_loop;

L_last_block:

	for (r=64;r<80;r+=2) {
		digests a-h update and permute round r:r+2
	}

	ctx->states += digests a-h;

	------------------------------------------------------------------------

	Apple CoreOS vector & numerics
*/
#if defined __x86_64__

	// associate variables with registers or memory

	#define	sp			%rsp
	#define	ctx			%rdi
	#define num_blocks	%rsi        // later move this to stack, use %rsi for temp variable u
	#define	data        %rdx

	#define	a			%r8
	#define	b			%r9
	#define	c			%r10
	#define	d			%r11
	#define	e			%r12
	#define	f			%r13
	#define	g			%r14
	#define	h			%r15

	#define	K			%rbx
    #define _num_blocks  (-48)(%rbp)        // rbx/r12-r15 
	#define	L_aligned_bswap	L_bswap(%rip)
	#define stack_size	(8+32*8+128)	    // 8 (_num_blocks) + ymm save/restore + WK(0:15)
	#define	ymm_save	128(sp)			    // starting address for ymm save/restore

	// 3 local variables
	#define	s	%rax
	#define	t	%rcx
	#define	u	%rsi

	// a window (16 quad-words) of message scheule
	#define	W0	%ymm0
	#define	W1	%ymm1
	#define	W2	%ymm2
	#define	W3	%ymm3

	// circular buffer for WK[(r:r+15)%16]
	#define WK(x)   (x&15)*8(sp)

// #define Ch(x,y,z)   (((x) & (y)) ^ ((~(x)) & (z)))

	.macro Ch
#if 1
    mov     $2, t
    xor     $1, t
    and     $0, t
    xor     $2, t
#else
	mov		$0, t		// x
	mov		$0, s		// x
	not		t			// ~x
	and		$1, s		// x & y
	and		$2, t		// ~x & z
	xor		s, t		// t = ((x) & (y)) ^ ((~(x)) & (z));
#endif
	.endm

// #define Maj(x,y,z)  (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

	.macro	Maj
	mov	 	$1,	t // y
	mov		$2,	s // z
	xor		$2,	t // y^z
	and		$1,	s // y&z
	and		$0, 	t // x&(y^z)
	xor		s,	t // Maj(x,y,z)
	.endm

// #define Gamma0(x)   (S64(1,  (x)) ^ S64(8, (x)) ^ R(7 ,   (x)))

	// performs Gamma0_512 on 4 quad-words on an ymm registers
	// use ymm6/ymm7 as intermediate registers
	.macro	Gamma0
	vpsrlq	$$1, $0, %ymm6		// part of S64(1, x)
	vpsllq	$$56, $0, %ymm7		// part of S64(8, x)
	vpsrlq	$$7, $0, $0			// R(7, x)
	vpxor	%ymm6, $0, $0
	vpsrlq	$$7, %ymm6, %ymm6	// part of S64(8, x)
	vpxor	%ymm7, $0, $0
	vpsllq	$$7, %ymm7, %ymm7	// part of S64(1, x)
	vpxor	%ymm6, $0, $0
	vpxor	%ymm7, $0, $0
	.endm

// #define Gamma1(x)   (S64(19, (x)) ^ S64(61, (x)) ^ R(6,   (x)))

	// performs Gamma1_512 on 4 words on an ymm registers
	// use ymm6/ymm7 as intermediate registers
	.macro	Gamma1
	vpsrlq	$$19, $0, %ymm6		// part of S64(19, x)
	vpsllq	$$3, $0, %ymm7		// part of S64(61, x)
	vpsrlq	$$6, $0, $0			// R(6, x)
	vpxor	%ymm6, $0, $0
	vpsrlq	$$42, %ymm6, %ymm6	// part of S64(61, x)
	vpxor	%ymm7, $0, $0
	vpsllq	$$42, %ymm7, %ymm7	// part of S64(19, x)
	vpxor	%ymm6, $0, $0
	vpxor	%ymm7, $0, $0
	.endm

    .macro  rightshift16
    vpxor   $1, $1, $1
    vperm2f128 $$33, $1, $0, $1
    .endm

    .macro  leftshift16
    vpxor   $1, $1, $1
    vperm2f128 $$2, $1, $0, $1
    .endm

    .macro  vpalignr8
    vpblendd $$3, $1, $0, $2 
    vpermq $$57, $2, $2
    .endm

    // W[r] = W[r-16] + Gamma1(W[r-2]) + W[r-7] + Gamma0(W[r-15]);
    /*
        W0 W1 W2 W3 
        update 4 quad words in W0 += vext(W2,W3,#8) + Gamma0(vext(W0,W1, #8)) + Gamma1(W1<<16);
                                W0 += Gamma1(vext(W3,W0, #16)). 
    */
    .macro  message_update4
    vpblendd $$3, $1, $0, %ymm5 
    vpxor   %ymm4, %ymm4, %ymm4
    vpermq $$57, %ymm5, %ymm5           // ymm5 = W[r-15] = vpalignr8 $0, $1, %ymm5
    vperm2f128 $$33, %ymm4, $3, %ymm4   // ymm4 = [W[16] W[17] 0 0] half of W[r-2] = rightshift16 $3, %ymm4
    Gamma0   %ymm5                  // Gamma0(W[r-15])
    Gamma1   %ymm4                  // Gamma1(W[r-2]) half
    vpaddq   %ymm5, $0, $0          // W0 += Gamma0([r-15]);
    vpblendd $$3, $3, $2, %ymm5
    vpaddq   %ymm4, $0, $0          // W0 += Gamma1(W[r-2]) + Gamma0(vext(W0,W1, #8));
    vpermq $$57, %ymm5, %ymm5       // W[r-7] = vpalignr8 $2, $3, %ymm5     // W[r-7]
    vpxor   %ymm4, %ymm4, %ymm4
    vpaddq   %ymm5, $0, $0          // W0 += W[r-7]
    vperm2f128 $$2, %ymm4, $0, %ymm4 // leftshift16 $0, %ymm4  for W0<<16
    Gamma1   %ymm4                  // Gamma1(W0<<16)
    vpaddq   %ymm4, $0, $0          // W0 += Gamma1(W0<<16);
    .endm 

// #define Sigma0(x)   (S64(28,  (x)) ^ S64(34, (x)) ^ S64(39, (x)))

	.macro	Sigma0
	rorx	$$28, $0, s		// S(28,  (x))
	rorx	$$34, $0, t		// S(34,  (x))
	rorx	$$11, s, u		// S(39,  (x))
	xor		s, t			// S(28,  (x)) ^ S(34, (x))
	xor		u, t		// t = (S(28,  (x)) ^ S(34, (x)) ^ S(39, (x)))
	.endm

// #define Sigma1(x)   (S(14,  (x)) ^ S(18, (x)) ^ S(41, (x)))

	.macro	Sigma1
	rorx	$$14, $0, s		// S(14,  (x))
	rorx	$$18, $0, t		// S(18,  (x))
	rorx	$$27, s, u		// S(41,  (x))
	xor		s, t			// S(14,  (x)) ^ S(18, (x))
	xor		u, t			// t = (S(14,  (x)) ^ S(18, (x)) ^ S(41, (x)))
	.endm

	// per round digests update
	.macro	round_ref
	Sigma1	$4				// t = T1
	add		t, $7			// use h to store h+Sigma1(e)
	Ch		$4, $5, $6		// t = Ch (e, f, g);
	add		$7, t			// t = h+Sigma1(e)+Ch(e,f,g);
	add		WK($8), t		// h = T1
	add		t, $3			// d += T1;
	mov		t, $7			// h = T1
	Sigma0	$0				// t = Sigma0(a);
	add		t, $7			// h = T1 + Sigma0(a);
	Maj		$0, $1, $2		// t = Maj(a,b,c)
	add		t, $7			// h = T1 + Sigma0(a) + Maj(a,b,c);
	.endm

	.macro	round

	rorx	$$14, $4, s		// S(14,  (x))
    mov     $6, t           // Ch(e,f,g) : 1
	rorx	$$18, $4, u		// S(18,  (x))
    xor     $5, t           // Ch(e,f,g) : 2
	xor		s, u			// S(14,  (x)) ^ S(18, (x))
    and     $4, t           // Ch(e,f,g) : 3
	rorx	$$27, s, s		// S(41,  (x))
    xor     $6, t           // t = Ch(e,f,g);
	xor		s, u			// u = Sigma1(e);
	add		t, $7			// h = h+Ch(e,f,g);
	add		u, $7			// h = h+Sigma1(e)+Ch(e,f,g);

	add		WK($8), $7		// h = T1
	add		$7, $3			// d += T1;

	rorx	$$28, $0, s		// S(28,  (x))
	rorx	$$34, $0, u		// S(34,  (x))
	xor		s, u			// S(28,  (x)) ^ S(34, (x))
	rorx	$$11, s, s		// S(39,  (x))
	xor		s, u	    	// t = (S(28,  (x)) ^ S(34, (x)) ^ S(39, (x)))
	add		u, $7			// h = T1 + Sigma0(a);

	mov	 	$1,	t           // b
	mov		$2,	s           // c
	xor		$2,	t           // b^c
	and		$1,	s           // b&c
	and		$0,	t           // a&(b^c)
	xor		s,	t           // t = Maj(a,b,c)

	add		t, $7			// h = T1 + Sigma0(a) + Maj(a,b,c);

	.endm

    /*
        16 rounds of hash update, update input schedule W (in vector register ymm0-ymm3) and WK = W + K (in stack)
    */
	.macro	rounds_schedule

    message_update4 W0, W1, W2, W3
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8
    vpaddq  0*32(K), W0, %ymm4
	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8
    vmovdqa %ymm4, WK(0)

    message_update4 W1, W2, W3, W0
	round	$4, $5, $6, $7, $0, $1, $2, $3, 4+$8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 5+$8
    vpaddq  1*32(K), W1, %ymm4
	round	$2, $3, $4, $5, $6, $7, $0, $1, 6+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 7+$8
    vmovdqa %ymm4, WK(4)

    message_update4 W2, W3, W0, W1
	round	$0, $1, $2, $3, $4, $5, $6, $7, 8+$8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 9+$8
    vpaddq  2*32(K), W2, %ymm4
	round	$6, $7, $0, $1, $2, $3, $4, $5, 10+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 11+$8
    vmovdqa %ymm4, WK(8)

    message_update4 W3, W0, W1, W2
	round	$4, $5, $6, $7, $0, $1, $2, $3, 12+$8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 13+$8
    vpaddq  3*32(K), W3, %ymm4
	round	$2, $3, $4, $5, $6, $7, $0, $1, 14+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 15+$8
    vmovdqa %ymm4, WK(12)

    addq    $$128, K
	.endm

    /*
        16 rounds of hash update, load new input schedule W (in vector register xmm0-xmm7) and update WK = W + K (in stack)
    */
	.macro	rounds_schedule_initial
    vmovdqu 0*32(data), W0
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
    vpshufb L_aligned_bswap, W0, W0
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8
    vpaddq  0*32(K), W0, %ymm4
	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8
    vmovdqa %ymm4, WK(0)

    
    vmovdqu 1*32(data), W1
	round	$4, $5, $6, $7, $0, $1, $2, $3, 4+$8
    vpshufb L_aligned_bswap, W1, W1
	round	$3, $4, $5, $6, $7, $0, $1, $2, 5+$8
    vpaddq  1*32(K), W1, %ymm4
	round	$2, $3, $4, $5, $6, $7, $0, $1, 6+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 7+$8
    vmovdqa %ymm4, WK(4)

    vmovdqu 2*32(data), W2
	round	$0, $1, $2, $3, $4, $5, $6, $7, 8+$8
    vpshufb L_aligned_bswap, W2, W2
	round	$7, $0, $1, $2, $3, $4, $5, $6, 9+$8
    vpaddq  2*32(K), W2, %ymm4

	round	$6, $7, $0, $1, $2, $3, $4, $5, 10+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 11+$8
    vmovdqa %ymm4, WK(8)

    vmovdqu 3*32(data), W3
	round	$4, $5, $6, $7, $0, $1, $2, $3, 12+$8
    vpshufb L_aligned_bswap, W3, W3
	round	$3, $4, $5, $6, $7, $0, $1, $2, 13+$8
    vpaddq  3*32(K), W3, %ymm4

	round	$2, $3, $4, $5, $6, $7, $0, $1, 14+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 15+$8
    vmovdqa %ymm4, WK(12)

    addq    $$128, K
    addq    $$128, data 
	.endm

    /*
        16 rounds of hash update
    */
	.macro	rounds_schedule_final
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8

	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8

	round	$4, $5, $6, $7, $0, $1, $2, $3, 4+$8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 5+$8

	round	$2, $3, $4, $5, $6, $7, $0, $1, 6+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 7+$8

	round	$0, $1, $2, $3, $4, $5, $6, $7, 8+$8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 9+$8

	round	$6, $7, $0, $1, $2, $3, $4, $5, 10+$8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 11+$8

	round	$4, $5, $6, $7, $0, $1, $2, $3, 12+$8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 13+$8

	round	$2, $3, $4, $5, $6, $7, $0, $1, 14+$8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 15+$8
	.endm

	.text
    .globl	_ccsha512_vng_intel_avx2_compress
_ccsha512_vng_intel_avx2_compress:

	// push callee-saved registers
	push	%rbp
    movq    %rsp, %rbp
	push	%rbx
	push	%r12
	push	%r13
	push	%r14
	push	%r15

	// allocate stack space
	sub		$stack_size, sp
    andq    $-32, sp                // aligned sp to 32-bytes

	// if kernel code, save used xmm registers
#if CC_KERNEL
	vmovdqa	%ymm0, 0*32+ymm_save
	vmovdqa	%ymm1, 1*32+ymm_save
	vmovdqa	%ymm2, 2*32+ymm_save
	vmovdqa	%ymm3, 3*32+ymm_save
	vmovdqa	%ymm4, 4*32+ymm_save
	vmovdqa	%ymm5, 5*32+ymm_save
	vmovdqa	%ymm6, 6*32+ymm_save
	vmovdqa	%ymm7, 7*32+ymm_save
#endif

    movq    num_blocks, _num_blocks

	// set up bswap parameters in the aligned stack space and pointer to table K512[]
	lea		_ccsha512_K(%rip), K

	// load W[0:15] into ymm0-ymm3
	vmovdqu	0*32(data), W0
	vmovdqu	1*32(data), W1
	vmovdqu	2*32(data), W2
	vmovdqu	3*32(data), W3
	addq	$128, data

    vmovdqa  L_aligned_bswap, %ymm4
	vpshufb	%ymm4, W0, W0
	vpshufb	%ymm4, W1, W1
	vpshufb	%ymm4, W2, W2
	vpshufb	%ymm4, W3, W3

	// compute WK[0:15] and save in stack
	vpaddq	0*32(K), W0, %ymm4
	vpaddq	1*32(K), W1, %ymm5
	vpaddq	2*32(K), W2, %ymm6
	vpaddq	3*32(K), W3, %ymm7
    addq	$128, K
	vmovdqa	%ymm4, WK(0)
	vmovdqa	%ymm5, WK(4)
	vmovdqa	%ymm6, WK(8)
	vmovdqa	%ymm7, WK(12)

L_loop:

	// digests a-h = ctx->states;
	mov		0*8(ctx), a
	mov		1*8(ctx), b
	mov		2*8(ctx), c
	mov		3*8(ctx), d
	mov		4*8(ctx), e
	mov		5*8(ctx), f
	mov		6*8(ctx), g
	mov		7*8(ctx), h

	// rounds 0:47 interleaved with W/WK update for rounds 16:63
    rounds_schedule a, b, c, d, e, f, g, h, 16
    rounds_schedule a, b, c, d, e, f, g, h, 32
    rounds_schedule a, b, c, d, e, f, g, h, 48
    rounds_schedule a, b, c, d, e, f, g, h, 64

	// revert K to the beginning of K256[]
	subq		$640, K
	subq		$1, _num_blocks				// num_blocks--

	je		L_final_block				// if final block, wrap up final rounds

    rounds_schedule_initial a, b, c, d, e, f, g, h, 0

	// ctx->states += digests a-h
	add		a, 0*8(ctx)
	add		b, 1*8(ctx)
	add		c, 2*8(ctx)
	add		d, 3*8(ctx)
	add		e, 4*8(ctx)
	add		f, 5*8(ctx)
	add		g, 6*8(ctx)
	add		h, 7*8(ctx)

	jmp		L_loop				// branch for next block

	// wrap up digest update round 48:63 for final block
L_final_block:
    rounds_schedule_final a, b, c, d, e, f, g, h, 0

	// ctx->states += digests a-h
	add		a, 0*8(ctx)
	add		b, 1*8(ctx)
	add		c, 2*8(ctx)
	add		d, 3*8(ctx)
	add		e, 4*8(ctx)
	add		f, 5*8(ctx)
	add		g, 6*8(ctx)
	add		h, 7*8(ctx)

	// if kernel, restore xmm0-xmm7
#if CC_KERNEL
	vmovdqa	0*32+ymm_save, %ymm0
	vmovdqa	1*32+ymm_save, %ymm1
	vmovdqa	2*32+ymm_save, %ymm2
	vmovdqa	3*32+ymm_save, %ymm3
	vmovdqa	4*32+ymm_save, %ymm4
	vmovdqa	5*32+ymm_save, %ymm5
	vmovdqa	6*32+ymm_save, %ymm6
	vmovdqa	7*32+ymm_save, %ymm7
#endif

	// free allocated stack memory
    leaq    -40(%rbp), sp

	// restore callee-saved registers
	pop		%r15
	pop		%r14
	pop		%r13
	pop		%r12
	pop		%rbx
	pop		%rbp

	// return
	ret

	// data for using ssse3 pshufb instruction (big-endian loading of data)
    .const
    .align  5

L_bswap:
    .quad   0x0001020304050607
    .quad   0x08090a0b0c0d0e0f
    .quad   0x1011121314151617
    .quad   0x18191a1b1c1d1e1f

#endif      // x86_64

#endif
