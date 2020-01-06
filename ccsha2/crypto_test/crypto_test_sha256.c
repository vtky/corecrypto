/*
 * Copyright (c) 2016,2017,2018 Apple Inc. All rights reserved.
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

#include <corecrypto/ccdigest.h>
#include <corecrypto/ccsha2.h>
#include "../ccdigest/crypto_test/crypto_test_digest.h"

const uint8_t CC_ALIGNED(8) ans0[] = {0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55,};
const uint8_t CC_ALIGNED(8) in0[] =  {};

const uint8_t CC_ALIGNED(8) ans1[] = {0x07,0x7b,0x18,0xfe,0x29,0x03,0x6a,0xda,0x48,0x90,0xbd,0xec,0x19,0x21,0x86,0xe1,0x06,0x78,0x59,0x7a,0x67,0x88,0x02,0x90,0x52,0x1d,0xf7,0x0d,0xf4,0xba,0xc9,0xab,};
const uint8_t CC_ALIGNED(8) in1[] =  {0x54,0x65,0x73,0x74,0x20,0x76,0x65,0x63,0x74,0x6f,0x72,0x20,0x66,0x72,0x6f,0x6d,0x20,0x66,0x65,0x62,0x6f,0x6f,0x74,0x69,0x2e,0x63,0x6f,0x6d,};

const uint8_t CC_ALIGNED(8) ans2[] = {0x16,0xf3,0xe2,0x07,0x16,0x29,0xd0,0x2b,0x0b,0xa9,0xe4,0xa4,0x36,0x43,0xf6,0x97,0x65,0x14,0xeb,0xd8,0xb4,0xb8,0xf0,0xf9,0xeb,0xf3,0xbd,0x7c,0xde,0x64,0x63,0xd8,};
const uint8_t CC_ALIGNED(8) in2[] =  {0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,0x45,0x46,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,0x45,0x46,
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,0x45,0x46,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,0x45,0x46,
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,0x45,0x46,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,0x45,0x46,
    0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,0x45,0x46,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x41,0x42,0x43,0x44,0x45,0x46,};

const uint8_t CC_ALIGNED(8) in3[] = {0x58, 0xe5, 0xa3, 0x25, 0x9c, 0xb0, 0xb6, 0xd1, 0x2c, 0x83, 0xf7, 0x23, 0x37, 0x9e, 0x35, 0xfd, 0x29, 0x8b, 0x60};
const uint8_t CC_ALIGNED(8) ans3[] = {0x9b, 0x5b, 0x37, 0x81, 0x6d, 0xe8, 0xfc, 0xdf, 0x3e, 0xc1, 0x0b, 0x74, 0x54, 0x28, 0x70, 0x8d, 0xf8, 0xf3, 0x91, 0xc5, 0x50, 0xea, 0x67, 0x46, 0xb2, 0xca, 0xfe, 0x01, 0x9c, 0x2b, 0x6a, 0xce,};

const uint8_t CC_ALIGNED(8) ans16383[] = {0xfa,0xb8,0x2f,0x13,0x52,0x40,0x5c,0x22,0xca,0x29,0x53,0xff,0x80,0xa5,0x08,0xe5,0x56,0x7c,0x51,0xe1,0xa9,0xae,0xb5,0x7c,0xf9,0xa5,0x64,0x47,0xe4,0x0b,0xa0,0x66,};

struct test_vector {
    size_t len;
    const uint8_t *input;
    const uint8_t *ans;
};
typedef struct test_vector test_vector_t;

test_vector_t test_vectors[] = {
    {0, in0, ans0},
    {28, in1, ans1},
    {128, in2, ans2},
    {19, in3, ans3},
};

static int sha256_16383(const struct ccdigest_info *di) {
    const size_t len = 16383;

    uint8_t ans[256/8];
    ccdigest_di_decl(di, dc);
    ccdigest_init(di, dc);

    for(size_t n=0; n<len; n++){
        uint8_t t= n&0xff;
        ccdigest_update(di, dc, 1, &t);
    }
    ccdigest_final(di, dc, ans);
    ccdigest_di_clear(di, dc);
    return memcmp(ans16383, ans, sizeof(ans)) == 0? 0 : -1;
}

static int sha256_oneshot(const struct ccdigest_info *di, int vect_num) {
    uint8_t ans[256/8];

    if(test_vectors[vect_num].input == NULL) return 0;
    ccdigest(di, test_vectors[vect_num].len, test_vectors[vect_num].input, ans);
    int rc =  memcmp(test_vectors[vect_num].ans, ans, sizeof(ans));
    return rc == 0? 0 : -1;
}

static int sha256_chunk(const struct ccdigest_info *di, int vect_num) {
    test_vector_t *v = test_vectors + vect_num;
    
    size_t total = v->len;
    size_t chunk = v->len/2;
    const uint8_t *p = v->input;
    uint8_t ans[256/8];
    ccdigest_di_decl(di, dc);
    ccdigest_init(di, dc);

    do {
        ccdigest_update(di, dc, chunk, p);
        total -= chunk;
        p += chunk;
        chunk /= 2;
        if(chunk == 0) chunk = total;
    } while(total);
    ccdigest_final(di, dc, ans);
    ccdigest_di_clear(di, dc);
    return memcmp(v->ans, ans, sizeof(ans)) == 0? 0 : -1;
}

static int sha256_test(const struct ccdigest_info *di){
    
    int n = sizeof(test_vectors)/sizeof(test_vectors[0]);
    int rc = 0;
    
    for(int i=0; i<n; i++){
        rc |= sha256_oneshot(di, i);
        rc |= sha256_chunk(di, i);
    }
    rc |= sha256_16383(di);
    
    return rc;
}

int sha256_kat(void){
   
    int rc;

    rc = sha256_test(ccsha256_di());
    rc |= sha256_test(&ccsha256_ltc_di);
    return rc;
}



