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
	This file provides x86_64 hand implementation of the following function

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
		- a circular window of message schedule W(r:r+15) is updated and stored in xmm0-xmm7 (or ymm0-ymm3/zmm0-zmm1 for avx1/avx2)
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
	#define stack_size	(8+16*12+128)	    // 8 (_num_blocks) + xmm0:xmm11 + WK(0:15)

	#define	L_aligned_bswap	L_bswap(%rip)   // bswap : big-endian loading of 4-byte words
	#define	xmm_save	128(sp)			    // starting address for xmm save/restore

	// 3 local variables
	#define	s	%rax
	#define	t	%rcx
	#define	u	%rsi

	// a window (16 quad-words) of message scheule
	#define	W0	%xmm0
	#define	W1	%xmm1
	#define	W2	%xmm2
	#define	W3	%xmm3
	#define	W4	%xmm4
	#define	W5	%xmm5
	#define	W6	%xmm6
	#define	W7	%xmm7

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

	// performs Gamma0_512 on 2 words on an xmm registers
	// use xmm8/xmm9 as intermediate registers
	.macro	Gamma0
	movdqa	$0, %xmm8
	movdqa	$0, %xmm9
	psrlq	$$7, $0			// R(7, x)
	psrlq	$$1, %xmm8		// part of S64(1, x)
	psllq	$$56, %xmm9		// part of S64(8, x)
	pxor	%xmm8, $0
	psrlq	$$7, %xmm8		// part of S64(8, x)
	pxor	%xmm9, $0
	psllq	$$7, %xmm9		// part of S64(1, x)
	pxor	%xmm8, $0
	pxor	%xmm9, $0
	.endm

// #define Gamma1(x)   (S64(19, (x)) ^ S64(61, (x)) ^ R(6,   (x)))

	// performs Gamma1_512 on 2 words on an xmm registers
	// use xmm8/xmm9 as intermediate registers
	.macro	Gamma1
	movdqa	$0, %xmm8
	movdqa	$0, %xmm9
	psrlq	$$6, $0			// R(6, x)
	psrlq	$$19, %xmm8		// part of S64(19, x)
	psllq	$$3, %xmm9		// part of S64(61, x)
	pxor	%xmm8, $0
	psrlq	$$42, %xmm8		// part of S64(61, x)
	pxor	%xmm9, $0
	psllq	$$42, %xmm9		// part of S64(19, x)
	pxor	%xmm8, $0
	pxor	%xmm9, $0
	.endm

    // W[r] = W[r-16] + Gamma1(W[r-2]) + W[r-7] + Gamma0(W[r-15]);
    /*
        W0 W1 W2 W3 W4 W5 W6 W7
        
        update 2 quad words in W0 = W0 + Gamma1(W7) + vext(W4,W5) + Gamma0(vext(W0,W1)). 
        use %xmm10, %xmm11 for temp
    */
    .macro  message_update2
    movdqa  $5, %xmm10
    movdqa  $1, %xmm11
    palignr $$8, $4, %xmm10     // vext(W4,W5)
    palignr $$8, $0, %xmm11     // vext(W0,W1)
    paddq   %xmm10, $0          // W0 + vext(W4,W5)
    movdqa  $7, %xmm10
    Gamma1  %xmm10              // Gamma1(W7)
    Gamma0  %xmm11              // Gamma0(vext(W0,W1))
    paddq   %xmm10, $0          // W0 + Gamma1(W7) + vext(W4,W5)
    paddq   %xmm11, $0          // W0 + Gamma1(W7) + vext(W4,W5) + Gamma0(vext(W0,W1))
    .endm 

// #define Sigma0(x)   (S64(28,  (x)) ^ S64(34, (x)) ^ S64(39, (x)))

	.macro	Sigma0
	mov		$0, t			// x
	mov		$0, s			// x
	ror		$$28, t			// S(28,  (x))
	ror		$$34, s			// S(34,  (x))
	xor		s, t			// S(28,  (x)) ^ S(34, (x))
	ror		$$5, s			// S(39,  (x))
	xor		s, t			// t = (S(28,  (x)) ^ S(34, (x)) ^ S(39, (x)))
	.endm

// #define Sigma1(x)   (S(14,  (x)) ^ S(18, (x)) ^ S(41, (x)))

	.macro	Sigma1
	mov		$0, s			// x
	ror		$$14, s			// S(14,  (x))
	mov		s, t			// S(14,  (x))
	ror		$$4, s			// S(18, (x))
	xor		s, t			// S(14,  (x)) ^ S(18, (x))
	ror		$$23, s			// S(41, (x))
	xor		s, t			// t = (S(14,  (x)) ^ S(18, (x)) ^ S(41, (x)))
	.endm

	// per round digests update
	.macro	round_ref
	Sigma1	$4				// t = Sigma1(e);
	add		t, $7			// h = h+Sigma1(e)
	Ch		$4, $5, $6		// t = Ch (e, f, g);
	add		t, $7			// h = h+Sigma1(e)+Ch(e,f,g);
	add		WK($8), $7		// h = h+Sigma1(e)+Ch(e,f,g)+WK
	add		$7, $3			// d += h;
	Sigma0	$0				// t = Sigma0(a);
	add		t, $7			// h += Sigma0(a);
	Maj		$0, $1, $2		// t = Maj(a,b,c)
	add		t, $7			// h = T1 + Sigma0(a) + Maj(a,b,c);
	.endm

	.macro	round
	mov		$4, s
	mov		$0, t
	ror		$$(41-18), s
	ror		$$(39-34), t
	xor		$4, s
	mov		$5, u
	xor		$0, t
	ror		$$(18-14), s
	xor		$6, u
	xor		$4, s
	ror		$$(34-28), t
	and		$4, u
	xor		$0, t
	xor		$6, u
	ror		$$14, s
	ror		$$28, t
	add		s, u
	mov		$0, s
	add		WK($8), u
	or		$2, s
	add		u, $7
	mov		$0, u
	add		$7, $3
	and		$1, s
	and		$2, u
	or		u, s
	add		t, $7
	add		s, $7	
	.endm

    /*
        16 rounds of hash update, update input schedule W (in vector register xmm0-xmm7) and WK = W + K (in stack)
    */
	.macro	rounds_schedule
    message_update2 W0, W1, W2, W3, W4, W5, W6, W7
    movdqa  0*16(K), %xmm8
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
    paddq   W0, %xmm8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8
    movdqa  %xmm8, WK(0)

    message_update2 W1, W2, W3, W4, W5, W6, W7, W0
    movdqa  1*16(K), %xmm8
	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
    paddq   W1, %xmm8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8
    movdqa  %xmm8, WK(2)

    message_update2 W2, W3, W4, W5, W6, W7, W0, W1
    movdqa  2*16(K), %xmm8
	round	$4, $5, $6, $7, $0, $1, $2, $3, 4+$8
    paddq   W2, %xmm8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 5+$8
    movdqa  %xmm8, WK(4)

    message_update2 W3, W4, W5, W6, W7, W0, W1, W2
    movdqa  3*16(K), %xmm8
	round	$2, $3, $4, $5, $6, $7, $0, $1, 6+$8
    paddq   W3, %xmm8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 7+$8
    movdqa  %xmm8, WK(6)

    message_update2 W4, W5, W6, W7, W0, W1, W2, W3
    movdqa  4*16(K), %xmm8
	round	$0, $1, $2, $3, $4, $5, $6, $7, 8+$8
    paddq   W4, %xmm8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 9+$8
    movdqa  %xmm8, WK(8)

    message_update2 W5, W6, W7, W0, W1, W2, W3, W4
    movdqa  5*16(K), %xmm8
	round	$6, $7, $0, $1, $2, $3, $4, $5, 10+$8
    paddq   W5, %xmm8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 11+$8
    movdqa  %xmm8, WK(10)

    message_update2 W6, W7, W0, W1, W2, W3, W4, W5
    movdqa  6*16(K), %xmm8
	round	$4, $5, $6, $7, $0, $1, $2, $3, 12+$8
    paddq   W6, %xmm8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 13+$8
    movdqa  %xmm8, WK(12)

    message_update2 W7, W0, W1, W2, W3, W4, W5, W6
    movdqa  7*16(K), %xmm8
	round	$2, $3, $4, $5, $6, $7, $0, $1, 14+$8
    paddq   W7, %xmm8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 15+$8
    movdqa  %xmm8, WK(14)

    addq    $$128, K
	.endm

    /*
        16 rounds of hash update, load new input schedule W (in vector register xmm0-xmm7) and update WK = W + K (in stack)
    */
	.macro	rounds_schedule_initial
    movdqu  0*16(data), W0
    movdqa  0*16(K), %xmm8
    pshufb  L_aligned_bswap, W0
	round	$0, $1, $2, $3, $4, $5, $6, $7, 0+$8
    paddq   W0, %xmm8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 1+$8
    movdqa  %xmm8, WK(0)

    movdqu  1*16(data), W1
    movdqa  1*16(K), %xmm8
    pshufb  L_aligned_bswap, W1
	round	$6, $7, $0, $1, $2, $3, $4, $5, 2+$8
    paddq   W1, %xmm8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 3+$8
    movdqa  %xmm8, WK(2)

    movdqu  2*16(data), W2
    movdqa  2*16(K), %xmm8
    pshufb  L_aligned_bswap, W2
	round	$4, $5, $6, $7, $0, $1, $2, $3, 4+$8
    paddq   W2, %xmm8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 5+$8
    movdqa  %xmm8, WK(4)

    movdqu  3*16(data), W3
    movdqa  3*16(K), %xmm8
    pshufb  L_aligned_bswap, W3
	round	$2, $3, $4, $5, $6, $7, $0, $1, 6+$8
    paddq   W3, %xmm8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 7+$8
    movdqa  %xmm8, WK(6)

    movdqu  4*16(data), W4
    movdqa  4*16(K), %xmm8
    pshufb  L_aligned_bswap, W4
	round	$0, $1, $2, $3, $4, $5, $6, $7, 8+$8
    paddq   W4, %xmm8
	round	$7, $0, $1, $2, $3, $4, $5, $6, 9+$8
    movdqa  %xmm8, WK(8)

    movdqu  5*16(data), W5
    movdqa  5*16(K), %xmm8
    pshufb  L_aligned_bswap, W5
	round	$6, $7, $0, $1, $2, $3, $4, $5, 10+$8
    paddq   W5, %xmm8
	round	$5, $6, $7, $0, $1, $2, $3, $4, 11+$8
    movdqa  %xmm8, WK(10)

    movdqu  6*16(data), W6
    movdqa  6*16(K), %xmm8
    pshufb  L_aligned_bswap, W6
	round	$4, $5, $6, $7, $0, $1, $2, $3, 12+$8
    paddq   W6, %xmm8
	round	$3, $4, $5, $6, $7, $0, $1, $2, 13+$8
    movdqa  %xmm8, WK(12)

    movdqu  7*16(data), W7
    movdqa  7*16(K), %xmm8
    pshufb  L_aligned_bswap, W7
	round	$2, $3, $4, $5, $6, $7, $0, $1, 14+$8
    paddq   W7, %xmm8
	round	$1, $2, $3, $4, $5, $6, $7, $0, 15+$8
    movdqa  %xmm8, WK(14)

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
    .globl	_ccsha512_vng_intel_ssse3_compress
_ccsha512_vng_intel_ssse3_compress:

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

	// if kernel code, save used xmm registers
#if CC_KERNEL
	movdqa	%xmm0, 0*16+xmm_save
	movdqa	%xmm1, 1*16+xmm_save
	movdqa	%xmm2, 2*16+xmm_save
	movdqa	%xmm3, 3*16+xmm_save
	movdqa	%xmm4, 4*16+xmm_save
	movdqa	%xmm5, 5*16+xmm_save
	movdqa	%xmm6, 6*16+xmm_save
	movdqa	%xmm7, 7*16+xmm_save
	movdqa	%xmm8, 8*16+xmm_save
	movdqa	%xmm9, 9*16+xmm_save
	movdqa	%xmm10, 10*16+xmm_save
	movdqa	%xmm11, 11*16+xmm_save
#endif

    movq    num_blocks, _num_blocks

	// set up bswap parameters in the aligned stack space and pointer to table K512[]
	lea		_ccsha512_K(%rip), K

	// load W[0:15] into xmm0-xmm7
	movdqu	0*16(data), W0
	movdqu	1*16(data), W1
	movdqu	2*16(data), W2
	movdqu	3*16(data), W3
	movdqu	4*16(data), W4
	movdqu	5*16(data), W5
	movdqu	6*16(data), W6
	movdqu	7*16(data), W7
	addq	$128, data

    movdqa  L_aligned_bswap, %xmm8
	pshufb	%xmm8, W0
	pshufb	%xmm8, W1
	pshufb	%xmm8, W2
	pshufb	%xmm8, W3
	pshufb	%xmm8, W4
	pshufb	%xmm8, W5
	pshufb	%xmm8, W6
	pshufb	%xmm8, W7

	// compute WK[0:15] and save in stack
	movdqa	0*16(K), %xmm8
	movdqa	1*16(K), %xmm9
	movdqa	2*16(K), %xmm10
	movdqa	3*16(K), %xmm11
	paddq	%xmm0, %xmm8
	paddq	%xmm1, %xmm9
	paddq	%xmm2, %xmm10
	paddq	%xmm3, %xmm11
	movdqa	%xmm8, WK(0)
	movdqa	%xmm9, WK(2)
	movdqa	%xmm10, WK(4)
	movdqa	%xmm11, WK(6)

	movdqa	4*16(K), %xmm8
	movdqa	5*16(K), %xmm9
	movdqa	6*16(K), %xmm10
	movdqa	7*16(K), %xmm11
	paddq	%xmm4, %xmm8
	paddq	%xmm5, %xmm9
	paddq	%xmm6, %xmm10
	paddq	%xmm7, %xmm11
	movdqa	%xmm8, WK(8)
	movdqa	%xmm9, WK(10)
	movdqa	%xmm10, WK(12)
	movdqa	%xmm11, WK(14)
    addq	$128, K

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
	movdqa	0*16+xmm_save, %xmm0
	movdqa	1*16+xmm_save, %xmm1
	movdqa	2*16+xmm_save, %xmm2
	movdqa	3*16+xmm_save, %xmm3
	movdqa	4*16+xmm_save, %xmm4
	movdqa	5*16+xmm_save, %xmm5
	movdqa	6*16+xmm_save, %xmm6
	movdqa	7*16+xmm_save, %xmm7
	movdqa	8*16+xmm_save, %xmm8
	movdqa	9*16+xmm_save, %xmm9
	movdqa	10*16+xmm_save, %xmm10
	movdqa	11*16+xmm_save, %xmm11
#endif

	// free allocated stack memory
	add		$stack_size, sp

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
    .align  4

L_bswap:
    .quad   0x0001020304050607
    .quad   0x08090a0b0c0d0e0f

#endif      // x86_64

#endif
