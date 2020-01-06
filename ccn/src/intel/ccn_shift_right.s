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


#if (defined(__x86_64__) && CCN_SHIFT_RIGHT_ASM)

        .text
	    .globl  _ccn_shift_right
        .align  4, 0x90
_ccn_shift_right:

        /* cc_unit ccn_shift_right(cc_size count, cc_unit *r, const cc_unit *s, size_t k) */

		// push rbp and set up frame base
        pushq   %rbp
        movq    %rsp, %rbp

		// symbolicate used registers

		#define	count	%rdi			// size in cc_unit (8-bytes)
		#define	dst 	%rsi			// destination
		#define	src		%rdx			// source 1

        #define v0      %xmm0
        #define v1      %xmm1
        #define v2      %xmm2
        #define v3      %xmm3
		#define	k		%xmm4			// for shift right
		#define	rk		%xmm5			// for shift left


        mov     $0, %rax
        cmp     $0, count
        je      0f                      // if count == 0, nothing to be done

        cmp     $0, %rcx
        jne     1f
        call    _ccn_set
        mov     $0, %rax
0:      popq    %rbp
        ret
1:
#if CC_KERNEL
        sub     $6*16, %rsp
        movdqa  %xmm0, 0*16(%rsp)
        movdqa  %xmm1, 1*16(%rsp)
        movdqa  %xmm2, 2*16(%rsp)
        movdqa  %xmm3, 3*16(%rsp)
        movdqa  %xmm4, 4*16(%rsp)
        movdqa  %xmm5, 5*16(%rsp)
#endif

        movq    %rcx, k
        subq    $64, %rcx
        negq    %rcx
        movq    %rcx, rk

        movq    (src), %rax
        shlq    %cl, %rax       // this is the final carry to be returned

        sub     $4, count
        jl      9f              // less than 4 elements
        je      8f              // with exact 4 elemnts to process, no more element to read

0:
        movdqu  0(src), v0
        movdqu  16(src), v1
        movdqu  8(src), v2
        movdqu  24(src), v3
        add     $2*16, src
        psrlq   k, v0
        psrlq   k, v1
        psllq   rk, v2
        psllq   rk, v3
        por     v2, v0
        por     v3, v1
        movdqu  v0, (dst)
        movdqu  v1, 16(dst)
        add     $2*16, dst
        sub     $4, count
        jg      0b
        jl      9f

8:      /* exactly 4 elements left */
        movdqu  0(src), v0
        movdqu  16(src), v1
        movdqu  8(src), v2
        movq    24(src), v3
        psrlq   k, v0
        psrlq   k, v1
        psllq   rk, v2
        psllq   rk, v3
        por     v2, v0
        por     v3, v1
        movdqu  v0, (dst)
        movdqu  v1, 16(dst)
        jmp     L_done


9:      add     $2, count       // post add 4, pre-sub 2
        jl      9f              // only 1 element left
        je      8f              // 2 element left

        /* 3 more elements */
        movdqu  0(src), v0
        movq    16(src), v1
        movdqu  8(src), v2
        psrlq   k, v0
        psrlq   k, v1
        psllq   rk, v2
        por     v2, v0
        movdqu  v0, (dst)
        movq    v1, 16(dst)
        jmp     L_done
8:
        /* 2 more elements */
        movdqu  0(src), v0
        movq    8(src), v2
        psrlq   k, v0
        psllq   rk, v2
        por     v2, v0
        movdqu  v0, (dst)
        jmp     L_done

9:
        /* 1 more elements */
        movq    0(src), v0
        psrlq   k, v0
        movq    v0, (dst)
L_done:
#if CC_KERNEL
        movdqa  0*16(%rsp), %xmm0
        movdqa  1*16(%rsp), %xmm1
        movdqa  2*16(%rsp), %xmm2
        movdqa  3*16(%rsp), %xmm3
        movdqa  4*16(%rsp), %xmm4
        movdqa  5*16(%rsp), %xmm5
        add     $6*16, %rsp
#endif
        popq    %rbp
        ret

#endif

