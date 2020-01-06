/*
 * Copyright (c) 2015,2016,2017,2018 Apple Inc. All rights reserved.
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
#include "testmore.h"
#include "testbyteBuffer.h"
#include <corecrypto/ccder.h>

#if (CCDER == 0)
entryPoint(ccder_tests, "ccder")
#else

//============================= ccder_sizeof ===================================

static void testSizeOf()
{
    is(ccder_sizeof(CCDER_EOL, 0), (size_t)2, "EOL");
    is(ccder_sizeof(CCDER_BOOLEAN, 0), (size_t)2, "BOOLEAN");
    is(ccder_sizeof(CCDER_INTEGER, 0), (size_t)2, "INTEGER");
    is(ccder_sizeof(CCDER_BIT_STRING, 0), (size_t)2, "BIT_STRING");
    is(ccder_sizeof(CCDER_OCTET_STRING, 0), (size_t)2, "OCTET_STRING");
    is(ccder_sizeof(CCDER_NULL, 0), (size_t)2, "NULL");
    is(ccder_sizeof(CCDER_OBJECT_IDENTIFIER, 0), (size_t)2, "OBJECT_IDENTIFIER");
    is(ccder_sizeof(CCDER_REAL, 0), (size_t)2, "REAL");
    is(ccder_sizeof(CCDER_ENUMERATED, 0), (size_t)2, "ENUMERATED");
    is(ccder_sizeof(CCDER_EMBEDDED_PDV, 0), (size_t)2, "EMBEDDED_PDV");
    is(ccder_sizeof(CCDER_UTF8_STRING, 0), (size_t)2, "UTF8_STRING");
    is(ccder_sizeof(CCDER_CONSTRUCTED_SEQUENCE, 0), (size_t)2, "CONSTRUCTED_SEQUENCE");
    is(ccder_sizeof(CCDER_CONSTRUCTED_SET, 0), (size_t)2, "CONSTRUCTED_SET");
    is(ccder_sizeof(CCDER_NUMERIC_STRING, 0), (size_t)2, "NUMERIC_STRING");
    is(ccder_sizeof(CCDER_PRINTABLE_STRING, 0), (size_t)2, "PRINTABLE_STRING");
    is(ccder_sizeof(CCDER_T61_STRING, 0), (size_t)2, "T61_STRING");
    is(ccder_sizeof(CCDER_VIDEOTEX_STRING, 0), (size_t)2, "VIDEOTEX_STRING");
    is(ccder_sizeof(CCDER_IA5_STRING, 0), (size_t)2, "IA5_STRING");
    is(ccder_sizeof(CCDER_UTC_TIME, 0), (size_t)2, "UTC_TIME");
    is(ccder_sizeof(CCDER_GENERALIZED_TIME, 0), (size_t)2, "GENERALIZED_TIME");
    is(ccder_sizeof(CCDER_GRAPHIC_STRING, 0), (size_t)2, "GRAPHIC_STRING");
    is(ccder_sizeof(CCDER_VISIBLE_STRING, 0), (size_t)2, "VISIBLE_STRING");
    is(ccder_sizeof(CCDER_GENERAL_STRING, 0), (size_t)2, "GENERAL_STRING");
    is(ccder_sizeof(CCDER_UNIVERSAL_STRING, 0), (size_t)2, "UNIVERSAL_STRING");
    is(ccder_sizeof(CCDER_BMP_STRING, 0), (size_t)2, "BMP_STRING");
    is(ccder_sizeof(CCDER_HIGH_TAG_NUMBER, 0), (size_t)3, "HIGH_TAG_NUMBER");
    is(ccder_sizeof(0x1f, 0), (size_t)3, "[31]");
    is(ccder_sizeof(0x20, 0), (size_t)3, "[32]");
    is(ccder_sizeof(0x7f, 0), (size_t)3, "[127]");
    is(ccder_sizeof(0x80, 0), (size_t)4, "[128]");
    is(ccder_sizeof(0x3fff, 0), (size_t)4, "[4095]");
    is(ccder_sizeof(0x4000, 0), (size_t)5, "[4096]");
    is(ccder_sizeof(0x1fffff, 0), (size_t)5, "[2097151]");
    is(ccder_sizeof(0x200000, 0), (size_t)6, "[2097152]");

    is(ccder_sizeof(CCDER_OCTET_STRING, 1), (size_t)3, "OCTET_STRING(1)");
    is(ccder_sizeof(CCDER_OCTET_STRING, 127), (size_t)129, "OCTET_STRING(127)");
    is(ccder_sizeof(CCDER_OCTET_STRING, 128), (size_t)131, "OCTET_STRING(128)");
    is(ccder_sizeof(CCDER_OCTET_STRING, 128), (size_t)131, "OCTET_STRING(129)");
}

//============================= ccder_sizeof_uint64 ============================

static void testSizeOfUInt64()
{
    is(ccder_sizeof_uint64(0), (size_t)3, "uint64(0)");
    is(ccder_sizeof_uint64(1), (size_t)3, "uint64(1)");
    is(ccder_sizeof_uint64(0x7f), (size_t)3, "uint64(0x7f)");
    is(ccder_sizeof_uint64(0x80), (size_t)4, "uint64(0x80)");
    is(ccder_sizeof_uint64(0x100), (size_t)4, "uint64(0x100)");
    is(ccder_sizeof_uint64(0x7fff), (size_t)4, "uint64(0x7fff)");
    is(ccder_sizeof_uint64(0x8000), (size_t)5, "uint64(0x8000)");
    is(ccder_sizeof_uint64(0x7fffff), (size_t)5, "uint64(0x7fffff)");
    is(ccder_sizeof_uint64(0x800000), (size_t)6, "uint64(0x800000)");
    is(ccder_sizeof_uint64(0x7fffffff), (size_t)6, "uint64(0x7fffffff)");
    is(ccder_sizeof_uint64(0x80000000), (size_t)7, "uint64(0x80000000)");
    is(ccder_sizeof_uint64(0x7fffffffff), (size_t)7, "uint64(0x7fffffffff)");
    is(ccder_sizeof_uint64(0x8000000000), (size_t)8, "uint64(0x8000000000)");
    is(ccder_sizeof_uint64(0x7fffffffffff), (size_t)8, "uint64(0x7fffffffffff)");
    is(ccder_sizeof_uint64(0x800000000000), (size_t)9, "uint64(0x800000000000)");
    is(ccder_sizeof_uint64(0x7fffffffffffff), (size_t)9, "uint64(0x7fffffffffffff)");
    is(ccder_sizeof_uint64(0x80000000000000), (size_t)10, "uint64(0x80000000000000)");
    is(ccder_sizeof_uint64(0x7fffffffffffffff), (size_t)10, "uint64(0x7fffffffffffffff)");
}

//================================ ccder_encode_len ============================

static int testEncodeLen(void)
{
    uint8_t tmp[5];

    // 1 byte
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result1[5]={0};
    is(ccder_encode_len(0,(const uint8_t*)&tmp[0],&tmp[1]),&tmp[0],"ccder_encode_len return value for 1byte length");
    ok_memcmp_or_fail(tmp, expected_result1,sizeof(tmp),"ccder_encode_len output for 1byte length");

    // 2 bytes
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result2[5]={0x81,0x80};
    is(ccder_encode_len(0x80,(const uint8_t*)&tmp[0],&tmp[2]),&tmp[0],"ccder_encode_len return value for 2byte length");
    ok_memcmp_or_fail(tmp, expected_result2,sizeof(tmp),"ccder_encode_len output for 2byte length");

    // 3 bytes
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result3[5]={0x82,0xFF,0xFE};
    is(ccder_encode_len(0xFFFE,(const uint8_t*)&tmp[0],&tmp[3]),&tmp[0],"ccder_encode_len return value for 3byte length");
    ok_memcmp_or_fail(tmp, expected_result3,sizeof(tmp),"ccder_encode_len output for 3byte length");

    // 4 bytes
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result4[5]={0x83,0xFF,0xFE,0xFD};
    is(ccder_encode_len(0xFFFEFD,(const uint8_t*)&tmp[0],&tmp[4]),&tmp[0],"ccder_encode_len return value for 4byte length");
    ok_memcmp_or_fail(tmp, expected_result4,sizeof(tmp),"ccder_encode_len output for 4byte length");

    // 5 bytes
    memset(tmp,0,sizeof(tmp));
    const uint8_t expected_result5[5]={0x84,0xFF,0xFE,0xFD,0xFC};
    is(ccder_encode_len(0xFFFEFDFC,(const uint8_t*)&tmp[0],&tmp[5]),&tmp[0],"ccder_encode_len return value for 5byte length");
    ok_memcmp_or_fail(tmp, expected_result5,sizeof(tmp),"ccder_encode_len output for 5byte length");

    if (sizeof(size_t)>4) {
        // 5 bytes
        is(ccder_encode_len((size_t)1<<33,&tmp[0],NULL),NULL, "length bigger than UINT32_MAX not supported"); // Expect error
    } else {
        pass("On 32bit platforms, the length can't exceed UINT32_MAX");
    }
    return 0;
}


//====================== ccder_decode_uint_n ===================================

typedef struct der_decode_uint_n_struct {
    char  *der_str_buf;
    cc_size n;
    int err;
} der_decode_uint_n_t;

der_decode_uint_n_t test_der_decode_uint_n[]={
    {"0200",0,1}, // Must have one byte content
    {"020100",0,0},
    {"020101",1,0},
    {"02020080",1,0},
    {"028109008000000000000001",ccn_nof_size(8),0},
    {"0281110080000000000000000000000000000001",ccn_nof_size(16),0},
    {"02020040",0,1},                   // Too many padding zeroes
    {"0203000080",1,1},                 // Too many padding zeroes
    {"02810A00000000000000000001",1,1}, // Too many padding zeroes
    {"0281088000000000000001",0,1},     // Negative
    };

static void testDecode_uint_n()
{
    for (size_t i=0;i<sizeof(test_der_decode_uint_n)/sizeof(test_der_decode_uint_n[0]);i++) {
        cc_size n=0;
        byteBuffer der_buf=hexStringToBytes(test_der_decode_uint_n[i].der_str_buf);
        uint8_t *der_end=der_buf->bytes+der_buf->len;
        if (!test_der_decode_uint_n[i].err) {
            is(ccder_decode_uint_n(&n,
                                   der_buf->bytes,
                                   der_end),
               der_end, "ccder_decode_uint_n return value");
            is(n,test_der_decode_uint_n[i].n, "ccder_decode_uint_n expected output");
        } else {
            is(ccder_decode_uint_n(&n,
                                   der_buf->bytes,
                                   der_end),
               NULL, "ccder_decode_uint_n return value");
        }
        free(der_buf);
    }
}

//====================== ccder_decode_uint64 ===================================

typedef struct der_decode_uint64_struct {
    char  *der_str_buf;
    uint64_t v;
    int err;
} der_decode_uint64_t;

der_decode_uint64_t test_der_decode_uint64[]={
    {"0200",0,1}, // Must have one byte content
    {"020100",0,0},
    {"020101",1,0},
    {"02020080",0x80,0},
    {"02084070605040302010",0x4070605040302010,0},
    {"0209008070605040302010",0x8070605040302010,0},
    {"0209018070605040302010",0x8070605040302010,1}, // Too big to be uint64_t
    {"02020040",1,1},                      // Too many padding zeroes
    {"0203000080",1,1},                    // Too many padding zeroes
    {"0281088000000000000001",0,1},        // Negative
    {"02810A00000000000000000001",1,1},    // Too many padding zeroes
    {"0281110001000000000000000000000000000001",0,1}, // Too big to be uint64_t
};

static void testDecode_uint64()
{
    for (size_t i=0;i<sizeof(test_der_decode_uint64)/sizeof(test_der_decode_uint64[0]);i++) {
        uint64_t computed_v=0;
        uint64_t expected_v=0;
        byteBuffer der_buf=hexStringToBytes(test_der_decode_uint64[i].der_str_buf);
        uint8_t *der_end=der_buf->bytes+der_buf->len;
        if (!test_der_decode_uint64[i].err) {
            expected_v=test_der_decode_uint64[i].v;
            is(ccder_decode_uint64(&computed_v,
                                   der_buf->bytes,
                                   der_end),
               der_end, "ccder_decode_uint64 return value");
            is(computed_v,expected_v, "ccder_decode_uint64 expected output");
        }
        else {
            is(ccder_decode_uint64(&computed_v,
                                   der_buf->bytes,
                                   der_end),
               NULL, "ccder_decode_uint64 return value");
        }
        free(der_buf);
    }
}

//====================== ccder_decode_uint ===================================

typedef struct der_decode_uint_struct {
    char  *der_str_buf;
    cc_unit v[CCN192_N];
    int err;
} der_decode_uint_t;

der_decode_uint_t test_der_decode_uint[]={
    {"0200",                        {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Must have one byte content
    {"020100",                      {CCN192_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00)},0},
    {"02020080",                    {CCN192_C(00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,80)},0},
    {"02020040",                    {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Too many padding zeroes
    {"0203000001",                  {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Too many padding zeroes
    {"02810A00000000000000000001",  {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Too many padding zeroes
    {"0281088000000000000001",      {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Negative
    {"02811901000000000000000000000000000000000000000000000000",
                                    {CCN192_C(ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff,ff)},1}, // Too big
};

static void testDecode_uint()
{
    for (size_t i=0;i<sizeof(test_der_decode_uint)/sizeof(test_der_decode_uint[0]);i++) {
        cc_unit computed_v[CCN192_N];
        byteBuffer der_buf=hexStringToBytes(test_der_decode_uint[i].der_str_buf);
        uint8_t *der_end=der_buf->bytes+der_buf->len;
        memset(computed_v,0xAA,sizeof(computed_v)); // Fill with a different value to start with.
        
        if (!test_der_decode_uint[i].err) {
            cc_unit *expected_v=test_der_decode_uint[i].v;
            is(ccder_decode_uint(CCN192_N,computed_v,
                                   der_buf->bytes,
                                   der_end),
               der_end, "ccder_decode_uint return value");
            ok_memcmp(computed_v,expected_v,sizeof(test_der_decode_uint[i].v), "ccder_decode_uint expected output");
        }
        else {
            is(ccder_decode_uint(CCN192_N, computed_v,
                                   der_buf->bytes,
                                   der_end),
               NULL, "ccder_decode_uint64 return value");
        }
        free(der_buf);
    }
}

const uint8_t derbuf1[] = { 0x30, 0x01, 0xAA };
const uint8_t derbuf2[] = { 0x30, 0x01, 0xAA, 0xBB }; // Too much data, but still valid
const uint8_t derbuf3[] = { 0x30, 0x03, 0xAA }; // No enough data for len
const uint8_t derbuf4[] = { 0x30, 0x84, 0xAA }; // Invalid length

typedef struct der_decode_tl_struct {
    const uint8_t  *der;
    size_t der_len;
    size_t next_der_offset; // 0 is test is invalid
    size_t end_der_offset;  // 0 is test is invalid
    const char *description;
} der_decode_tl_t;

der_decode_tl_t test_der_decode_tl[] = {
    {&derbuf1[0],0,0,0,"Wrong der_end"},
    {&derbuf1[0],1,0,0,"Wrong der_end"},
    {&derbuf1[0],2,0,0,"Wrong der_end"},
    {&derbuf1[0],sizeof(derbuf1),2,3,"valid test, exactly enough data"},
    {&derbuf2[0],sizeof(derbuf2),2,3,"valid test, too much data"},
    {&derbuf3[0],sizeof(derbuf3),0,0,"No enough data for length"},
    {&derbuf4[0],sizeof(derbuf4),0,0,"Invalid length"},

};

static void testDecode_tl()
{
    for (size_t i=0;i<sizeof(test_der_decode_tl)/sizeof(test_der_decode_tl[0]);i++) {
        const der_decode_tl_t test=test_der_decode_tl[i];
        const uint8_t *der_end=test.der+test.der_len;
        const uint8_t *der_body_end=NULL;
        const uint8_t *expected_return=NULL; // for errors
        const uint8_t *expected_body_end=test.der; // for errors
        if (test.next_der_offset) {
            expected_return=test.der+test.next_der_offset;
            expected_body_end=test.der+test.end_der_offset;
        }

        is(ccder_decode_constructed_tl(CCDER_CONSTRUCTED_SEQUENCE,&der_body_end,
                                       test.der,der_end),expected_return,
                                       "%zu: %s",i, test.description);
        is(der_body_end,expected_body_end, "%zu: %s",i, test.description);
    }
}

//=============================== MAIN ccder ===================================

int ccder_tests(TM_UNUSED int argc, TM_UNUSED char *const *argv)
{
    plan_tests(123);

    testDecode_tl();
    testSizeOfUInt64();
    testSizeOf();
    testEncodeLen();
    testDecode_uint();
    testDecode_uint_n();
    testDecode_uint64();
    return 0;
}

#endif //entryPoint(ccder,"ccder")

