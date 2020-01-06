/*
 * Copyright (c) 2010,2011,2015,2016,2017,2018 Apple Inc. All rights reserved.
 *
 * corecrypto Internal Use License Agreement
 *
 * IMPORTANT:  This Apple corecrypto software is supplied to you by Apple Inc. ("Apple")
 * in consideration of your agreement to the following terms, and your download or use
 * of this Apple software constitutes acceptance of these terms.  If you do not agree
 * with these terms, please do not download or use this Apple software.
 *
 * 1.    As used in this Agreement, the term "Apple Software" collectively means and
 * includes all of the Apple corecrypto materials provided by Apple here, including
 * but not limited to the Apple corecrypto software, frameworks, libraries, documentation
 * and other Apple-created materials. In consideration of your agreement to abide by the
 * following terms, conditioned upon your compliance with these terms and subject to
 * these terms, Apple grants you, for a period of ninety (90) days from the date you
 * download the Apple Software, a limited, non-exclusive, non-sublicensable license
 * under Apple’s copyrights in the Apple Software to make a reasonable number of copies
 * of, compile, and run the Apple Software internally within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software; provided
 * that you must retain this notice and the following text and disclaimers in all
 * copies of the Apple Software that you make. You may not, directly or indirectly,
 * redistribute the Apple Software or any portions thereof. The Apple Software is only
 * licensed and intended for use as expressly stated above and may not be used for other
 * purposes or in other contexts without Apple's prior written permission.  Except as
 * expressly stated in this notice, no other rights or licenses, express or implied, are
 * granted by Apple herein.
 *
 * 2.    The Apple Software is provided by Apple on an "AS IS" basis.  APPLE MAKES NO
 * WARRANTIES, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION THE IMPLIED WARRANTIES
 * OF NON-INFRINGEMENT, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, REGARDING
 * THE APPLE SOFTWARE OR ITS USE AND OPERATION ALONE OR IN COMBINATION WITH YOUR PRODUCTS,
 * SYSTEMS, OR SERVICES. APPLE DOES NOT WARRANT THAT THE APPLE SOFTWARE WILL MEET YOUR
 * REQUIREMENTS, THAT THE OPERATION OF THE APPLE SOFTWARE WILL BE UNINTERRUPTED OR
 * ERROR-FREE, THAT DEFECTS IN THE APPLE SOFTWARE WILL BE CORRECTED, OR THAT THE APPLE
 * SOFTWARE WILL BE COMPATIBLE WITH FUTURE APPLE PRODUCTS, SOFTWARE OR SERVICES. NO ORAL
 * OR WRITTEN INFORMATION OR ADVICE GIVEN BY APPLE OR AN APPLE AUTHORIZED REPRESENTATIVE
 * WILL CREATE A WARRANTY.
 *
 * 3.    IN NO EVENT SHALL APPLE BE LIABLE FOR ANY DIRECT, SPECIAL, INDIRECT, INCIDENTAL
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) ARISING
 * IN ANY WAY OUT OF THE USE, REPRODUCTION, COMPILATION OR OPERATION OF THE APPLE
 * SOFTWARE, HOWEVER CAUSED AND WHETHER UNDER THEORY OF CONTRACT, TORT (INCLUDING
 * NEGLIGENCE), STRICT LIABILITY OR OTHERWISE, EVEN IF APPLE HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * 4.    This Agreement is effective until terminated. Your rights under this Agreement will
 * terminate automatically without notice from Apple if you fail to comply with any term(s)
 * of this Agreement.  Upon termination, you agree to cease all use of the Apple Software
 * and destroy all copies, full or partial, of the Apple Software. This Agreement will be
 * governed and construed in accordance with the laws of the State of California, without
 * regard to its choice of law rules.
 *
 * You may report security issues about Apple products to product-security@apple.com,
 * as described here:  https://www.apple.com/support/security/.  Non-security bugs and
 * enhancement requests can be made via https://bugreport.apple.com as described
 * here: https://developer.apple.com/bug-reporting/
 *
 * EA1350
 * 10/5/15
 */

/*
 * Parts of this code adapted from LibTomCrypt
 *
 * LibTomCrypt, modular cryptographic library -- Tom St Denis
 *
 * LibTomCrypt is a library that provides various cryptographic
 * algorithms in a highly modular and flexible manner.
 *
 * The library is free for all purposes without any express
 * guarantee it works.
 *
 * Tom St Denis, tomstdenis@gmail.com, http://libtom.org
 */

#include <corecrypto/ccsha2.h>
#include <corecrypto/cc_priv.h>
#include "ccsha2_internal.h"

// Various logical functions
#define Ch(x,y,z)       (z ^ (x & (y ^ z)))
#define Maj(x,y,z)      (((x | y) & z) | (x & y))
#define S(x, n)         ror((x),(n))
#define R(x, n)         ((x)>>(n))

#define Sigma0(x)       (S(x, 2) ^ S(x, 13) ^ S(x, 22))
#define Sigma1(x)       (S(x, 6) ^ S(x, 11) ^ S(x, 25))

#define Gamma0(x)       (S(x, 7)  ^ S(x, 18) ^ R(x, 3))
#define Gamma1(x)       (S(x, 17) ^ S(x, 19) ^ R(x, 10))

//It is beter if the following macros are defined as inline functions,
//but I found some compilers do not inline them.
#ifdef __CC_ARM
    #define ror(val, shift) __ror(val,shift)
#else
    #define ror(val, shift) ((val >> shift) | (val << (32 - shift)))
#endif

#ifdef __CC_ARM
    #define byte_swap32(x) __rev(x)
#elif defined(__clang__) && !defined(_MSC_VER)
    #define byte_swap32(x) __builtin_bswap32(x);
#else
   #define byte_swap32(x) ((ror(x, 8) & 0xff00ff00) | (ror(x, 24) & 0x00ff00ff))
#endif

#if CC_HANDLE_UNALIGNED_DATA
    #define set_W(i) CC_LOAD32_BE(W[i], buf + (4*(i)))
#else
    #define set_W(i) W[i] = byte_swap32(buf[i])
#endif

// the round function
#define RND(a,b,c,d,e,f,g,h,i)                                 \
    t0 = h + Sigma1(e) + Ch(e, f, g) + ccsha256_K[i] + W[i];   \
    t1 = Sigma0(a) + Maj(a, b, c);                             \
    d += t0;                                                   \
    h  = t0 + t1;

// compress 512-bits 
void ccsha256_ltc_compress(ccdigest_state_t state, size_t nblocks, const void *in)
{
    uint32_t W[64], t0, t1;
    uint32_t S0,S1,S2,S3,S4,S5,S6,S7;
    int i;
    uint32_t *s = ccdigest_u32(state);
#if CC_HANDLE_UNALIGNED_DATA
    const unsigned char *buf = in;
#else
    const uint32_t *buf = in;
#endif

    while(nblocks--) {

        // schedule W 0..15
        set_W(0); set_W(1); set_W(2); set_W(3); set_W(4); set_W(5); set_W(6); set_W(7);
        set_W(8); set_W(9); set_W(10);set_W(11);set_W(12);set_W(13);set_W(14);set_W(15);

        // schedule W 16..63
        for (i = 16; i < 64; i++) {
            W[i] = Gamma1(W[i - 2]) + W[i - 7] + Gamma0(W[i - 15]) + W[i - 16];
        }

        // copy state into S
        S0= s[0];
        S1= s[1];
        S2= s[2];
        S3= s[3];
        S4= s[4];
        S5= s[5];
        S6= s[6];
        S7= s[7];

        // Compress
        for (i = 0; i < 64; i += 8) {
            RND(S0,S1,S2,S3,S4,S5,S6,S7,i+0);
            RND(S7,S0,S1,S2,S3,S4,S5,S6,i+1);
            RND(S6,S7,S0,S1,S2,S3,S4,S5,i+2);
            RND(S5,S6,S7,S0,S1,S2,S3,S4,i+3);
            RND(S4,S5,S6,S7,S0,S1,S2,S3,i+4);
            RND(S3,S4,S5,S6,S7,S0,S1,S2,i+5);
            RND(S2,S3,S4,S5,S6,S7,S0,S1,i+6);
            RND(S1,S2,S3,S4,S5,S6,S7,S0,i+7);
        }
        
        // feedback
        s[0] += S0;
        s[1] += S1;
        s[2] += S2;
        s[3] += S3;
        s[4] += S4;
        s[5] += S5;
        s[6] += S6;
        s[7] += S7;

        buf+=CCSHA256_BLOCK_SIZE/sizeof(buf[0]);
    }
}
