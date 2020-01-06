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

#include "cavs_common.h"
#include "cavs_dispatch.h"

#include "cavs_op_rsa_key_gen.h"
#include "cavs_op_rsa_sig_gen.h"
#include "cavs_op_rsa_verify.h"

#import <corecrypto/ccn.h>
#import <corecrypto/ccrsa.h>
#import <corecrypto/ccrsa_priv.h>
#import <corecrypto/ccrng.h>
#import <corecrypto/ccrng_system.h>
#import <corecrypto/ccsha1.h>
#import <corecrypto/ccsha2.h>
#import <corecrypto/cczp.h>
#import <corecrypto/ccrng_sequence.h>
#import <corecrypto/ccrng_rsafips_test.h>

#import "CavsRSATests.h"

/*
 * This test generates keys locally and dispatches them in DER serialized form
 * to the remote target.  It's ugly and so are the RSA key generation
 * operations involved.
 */
static uint32_t kExponentValue = 65537;
static NSData* gCurrentModulus = NULL;
static ccrsa_pub_ctx_t gCurrentPublicKey = NULL;
static ccrsa_full_ctx_t gCurrentPrivateKey = NULL;
static NSNumber* gCurrentRSAKeySize = nil;

@interface CavsRSATests (PrivateMethods)

+ (NSData *)currentModulus;
+ (NSNumber *)currentKeySize;

- (ccrsa_full_ctx_t)currentPrivateKey:(NSNumber *)rsaKeySize;

- (BOOL)runKeyGenTest:(TestFileData *)testData withCounter:(NSInteger)counter;

- (BOOL)RSAKeyGenTypeProbPrime:(TestFileData *)testData;
- (BOOL)RSAKeyGenTypeRandPrimeKAT:(TestFileData *)testData;
- (BOOL)RSAKeyGenTypeProbPrimeWithCondition:(TestFileData *)testData;

- (void)output_zp:(NSString *)name n:(size_t) n  src:(const cc_unit *)source;

- (BOOL)runSigGenTest:(TestFileData *)testData withCounter:(NSInteger)counter;

- (BOOL)runSigVerTest:(TestFileData *)testData withCounter:(NSInteger)counter;
@end

@implementation CavsRSATests

@synthesize  testType = _testType;
@synthesize  keySize = _keySize;

+ (NSData *)currentModulus
{
    return gCurrentModulus;
}

+ (void)setupTest
{
    return;
}

+ (NSNumber *)currentKeySize
{
    return gCurrentRSAKeySize;
}

+ (void)cleanUpTest
{
    if (gCurrentRSAKeySize != nil) {
        [gCurrentRSAKeySize release];
        gCurrentRSAKeySize = nil;
    }

    if (gCurrentModulus != nil) {
        [gCurrentModulus release];
        gCurrentModulus = nil;
    }

    if (gCurrentPublicKey != NULL) {
        free(gCurrentPublicKey);
        gCurrentPublicKey = NULL;
    }

    if (gCurrentPrivateKey != NULL) {
        free(gCurrentPrivateKey);
        gCurrentPrivateKey = NULL;
    }
}

- (id)initWithFileParser:(TestFileParser *)fileParser
      withTestDictionary:(NSDictionary *)testsToRun
{
    return [super initWithFileParser:fileParser withTestDictionary:testsToRun];
}

- (void)output_zp: (NSString *)name n:(size_t) n  src:(const cc_unit *)source
{
    size_t len;
    size_t dest_len = n * sizeof(cc_unit);
    uint8_t dest[dest_len];

    if((len = ccn_write_uint_size(n, source)) > dest_len) {
        errorf("len exceeded buffer");
        return;
    }

    dest_len = len;
    ccn_write_uint(n, source, dest_len, dest);

    [self outputFormat:name, BufToHexString(dest, dest_len)];
}

/*
 * Return back the current cached private key, or generate (and log) a new one
 * as necessary.
 *
 * Despite the tests being remote, the key is generated and cached locally for
 * the signature generation test so that it can be supplied to multiple calls
 * in a row, without generating a new (expensive) key each time.
 */
- (ccrsa_full_ctx_t)currentPrivateKey:(NSNumber *)rsaKeySize
{
    NSAutoreleasePool *localPool = [NSAutoreleasePool new];

    if (!rsaKeySize) {
        [localPool drain];
        errorf("returning nil because rsaKeySize is nil");
        return NULL;
    }

    BOOL generateNewKey = NO;

    if      (!gCurrentRSAKeySize)                               generateNewKey = YES;
    else if (![rsaKeySize isEqualToNumber:gCurrentRSAKeySize])  generateNewKey = YES;
    else if (!gCurrentPrivateKey)                               generateNewKey = YES;

    if (!generateNewKey) {
        [localPool drain];
        return gCurrentPrivateKey;
    }

    if (gCurrentPrivateKey != NULL) {
        free(gCurrentPrivateKey);
        gCurrentPrivateKey = NULL;
    }

    // We need to generate a new key
    [gCurrentRSAKeySize release];
    gCurrentRSAKeySize = [rsaKeySize copy];

    size_t keySize = (size_t)[gCurrentRSAKeySize unsignedIntValue];
    size_t nbits = keySize;
    size_t context_size = ccrsa_full_ctx_size(ccn_sizeof(nbits));

    gCurrentPrivateKey = (ccrsa_full_ctx_t)malloc(context_size);
    memset(gCurrentPrivateKey, 0, context_size);

    cc_size n = ccn_nof(nbits);
    ccrsa_ctx_n(gCurrentPrivateKey) = n;

    struct ccrng_state *theRng1 = ccrng(NULL);
    struct ccrng_state *theRng2 = ccrng(NULL);

    cc_unit cc_unit_e = (cc_unit)kExponentValue;
    size_t eSize = ccn_write_int_size(1, &cc_unit_e);

    uint8_t eBytes[eSize];
    ccn_write_int(1, &cc_unit_e, eSize, eBytes);

    int ret = ccrsa_generate_fips186_key(nbits, gCurrentPrivateKey, eSize,
            eBytes, theRng1, theRng2);
    if (ret) {
        [localPool drain];
        errorf("returning nil, failed to generate key (%d)", ret);
        return NULL;
    }

    size_t modulusLength = (keySize / 8);
    uint8_t modulus[modulusLength];
    size_t exponentLength = modulusLength;
    uint8_t exponent[exponentLength];

    ret = ccrsa_get_pubkey_components(ccrsa_ctx_public(gCurrentPrivateKey),
            modulus, &modulusLength, exponent, &exponentLength);

    if (ret) {
        [localPool drain];
        errorf("returning nil, failed to get the public key components");
        return NULL;
    }

    // print out the required data
    [self outputFormat:@"n = %@", BufToHexString(modulus, modulusLength)];
    [self outputString:nil];

    [self outputString:@"e = 010001"];
    [self outputString:nil];

    [localPool drain];
    return (ccrsa_full_ctx_t)gCurrentPrivateKey;
}

- (BOOL)runTest:(TestFileData *)testData withCounter:(NSInteger)counter
{
    BOOL result = NO;
    if (!testData)    return result;

    TFTestType testType = testData.testType;
    self.testType       = testType;
    self.keySize        = [testData.rsaKeySize integerValue];

    switch(testType) {
    case TTRSAKeyGeneration:
        result = [self runKeyGenTest:testData withCounter:counter];
        break;

    case TTRSASignatureVerification:
        result = [self runSigVerTest:testData withCounter:counter];
        break;

    case TTRSASignatureGeneration:
        result = [self runSigGenTest:testData withCounter:counter];
        break;

    default:
        errorf("Unknown test type for RSA test: %d", (int)testType);
        break;
    }
    return result;
}

/*
 * There are three keygen test files:
 *   CAVS_VECTOR_RSA_KEY_GEN - TRSAKeyGenTypeProbPrimeWithCondition:
 *      KeyGen_186-3.req   rsa2vs.pdf, Section 6.2.1
 *      NIST.FIPS, 186-4.pdf, Section B.3.6: Generation of Probable Primes with Conditions Based on Auxiliary Probable Primes
 *   NOT SUPPORTED - TRSAKeyGenTypeRandProbPrime
 *      KeyGen_RandomProbablyPrime3_3.req
 *      rsa2vs.pdf, Section 6.2.2.2 The KeyGen_RandomProbablyPrime3_3 test for Appendix B.3.3
 *   NOT SUPPORTED - TRSAKeyGenTypeRandProbPrimeKAT
 *      KeyGen3_3_KAT.req
 *      rsa2vs.pdf, Section 6.2.2.1 The Known Answer Test for B.3.3 Probably Primes
 */
- (BOOL)runKeyGenTest:(TestFileData *)testData withCounter:(NSInteger)counter
{
    int rounds;

    rounds = [testData.numKeys intValue];

    if (testData.rsaKeyGenType != TRSAKeyGenTypeProbPrimeWithCondition) {
        errorf("Not implemented");
        return NO;
    }

    for (int i = 0; i < rounds; i++) {
        [self RSAKeyGenTypeProbPrimeWithCondition:testData];
    }

    [self outputString:nil];
    return YES;
}

- (BOOL)RSAKeyGenTypeProbPrimeWithCondition:(TestFileData *)testData
{
    size_t key_sz = [testData.rsaKeySize intValue];

    uint32_t trace_len = sizeof(struct ccrsa_fips186_trace) * CCRSA_FIPS186_TRACE_NUM;
    struct ccrsa_fips186_trace *trace = NULL;
    ccrsa_full_ctx_decl(ccn_sizeof(key_sz), fk);

    struct cavs_op_rsa_key_gen request;
    memset(&request, 0, sizeof(struct cavs_op_rsa_key_gen));
    request.vector = CAVS_VECTOR_RSA_KEY_GEN;
    request.key_sz = (uint32_t)key_sz;

    size_t len = 0;
    uint8_t *wksp = NULL;
    int ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        return NO;
    }
    if (len < (trace_len + sizeof(uint32_t))) {
        errorf("length too small");
        return NO;
    }

    trace = (struct ccrsa_fips186_trace *)wksp;

    /* The DER encoded key is present after the trace data. */
    uint32_t *key_len = (uint32_t *)((uint8_t *)trace + trace_len);
    uint8_t *key_buf = (uint8_t *)(key_len + 1);
    if (key_buf + *key_len > (wksp + len)) {
        errorf("trucated");
        return NO;
    }

    if (ccn_sizeof_n(ccrsa_import_priv_n(*key_len, key_buf)) != ccn_sizeof(key_sz)) {
        errorf("key sizes don't match, expected %lu, got %lu", ccn_sizeof(key_sz),
                ccn_sizeof_n(ccrsa_import_priv_n(*key_len, key_buf)));
        errorf("continuing...");
    }

    /* Prime the 'n' on the fk before loading the DER. */
    ccrsa_ctx_n(fk) = ccrsa_import_priv_n(*key_len, key_buf);

    if (ccrsa_import_priv(fk, *key_len, key_buf) != 0) {
        errorf("failed to import key");
        return NO;
    }

    const cc_size n = ccrsa_ctx_n(fk);

    if (n > CCRSA_FIPS186_TRACE_MAX_KEY_UNITS) {
        errorf("failed to generate appropriate key size, got %zu expected %lu",
                n, CCRSA_FIPS186_TRACE_MAX_KEY_UNITS);
        return NO;
    }

    [self output_zp:@"e = %@" n:n src:ccrsa_ctx_e(fk)];

    /* Output the two trace segments. */
    int i = 0;
    [self outputFormat:@"%@%zu", @"bitlen1 = ", trace[i].bitlen1];
    [self output_zp:@"Xp1 = %@" n:n src:trace[i].xp1];
    [self outputFormat:@"%@%zu", @"bitlen2 = ", trace[i].bitlen2];
    [self output_zp:@"Xp2 = %@" n:n src:trace[i].xp2];
    [self output_zp:@"Xp = %@" n:n src:trace[i].xp];
    [self output_zp:@"p = %@" n:n src:trace[i].p];

    i = 1;
    [self outputFormat:@"%@%zu", @"bitlen3 = ", trace[i].bitlen1];
    [self output_zp:@"Xq1 = %@" n:n src:trace[i].xp1];
    [self outputFormat:@"%@%zu", @"bitlen4 = ", trace[i].bitlen2];
    [self output_zp:@"Xq2 = %@" n:n src:trace[i].xp2];
    [self output_zp:@"Xq = %@" n:n src:trace[i].xp];
    [self output_zp:@"q = %@" n:n src:trace[i].p];

    [self output_zp:@"n = %@" n:n src:ccrsa_ctx_m(fk)];
    [self output_zp:@"d = %@" n:n src:ccrsa_ctx_d(fk)];
    [self outputString:@" "];

out:
    return YES;
}

- (BOOL)runSigGenTest:(TestFileData *)testData withCounter:(NSInteger)counter
{
    BOOL result = NO;
    size_t sig_len;
    size_t key_size;

    /* Get the cached private key to send to the remote target. */
    ccrsa_full_ctx_t priv_key = [self currentPrivateKey:testData.rsaKeySize];
    sig_len = CC_BITLEN_TO_BYTELEN([testData.rsaKeySize unsignedIntValue]);
    key_size = (size_t)[testData.rsaKeySize unsignedIntValue];

    /* Construct the request. */
    struct cavs_op_rsa_sig_gen request;
    memset(&request, 0, sizeof(struct cavs_op_rsa_sig_gen));

    request.vector = CAVS_VECTOR_RSA_SIG_GEN;
    request.digest = CipherTypeToDigest(testData.shaAlgo);
    request.key_len = (uint32_t)ccrsa_export_priv_size(priv_key);
    request.key = malloc(request.key_len);
    request.message_len = (uint32_t)[testData.msg length];
    request.message = (uint8_t *)[testData.msg bytes];

    /* Populate the request.key with the cached private key. */
    if (ccrsa_export_priv(priv_key, request.key_len, request.key) != 0) {
        errorf("export_priv failed");
        goto out;
    }

    size_t len = sig_len;
    uint8_t *wksp = NULL;
    int ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        goto out;
    }

    [self outputFormat:@"SHAAlg = %@", CipherTypeToString(testData.shaAlgo)];
    [self outputFormat:@"Msg = %@", DataToHexString(testData.msg)];
    [self outputFormat:@"S = %@", BufToHexString(wksp, sig_len)];
    [self outputString:nil];

    result = YES;

out:
    free(request.key);

    return result;
}

- (BOOL)runSigVerTest:(TestFileData *)testData
          withCounter:(NSInteger)counter
{
    uint32_t valid;

    // initialize the request structure
    struct cavs_op_rsa_verify request;
    memset(&request, 0, sizeof(struct cavs_op_rsa_verify));

    request.vector = CAVS_VECTOR_RSA_VERIFY;
    request.digest = CipherTypeToDigest(testData.shaAlgo);
    request.key_sz = (uint32_t)[testData.rsaKeySize unsignedIntValue];
    request.modulus_len = (uint32_t)[testData.nData length];
    request.modulus = (uint8_t *)[testData.nData bytes];
    request.message_len = (uint32_t)[testData.msg length];
    request.message = (uint8_t *)[testData.msg bytes];
    request.signature_len = (uint32_t)[testData.sData length];
    request.signature = (uint8_t *)[testData.sData bytes];

    /*
     * The exponent is packed into a 0-prefixed string and can be anywhere from
     * 16 bits to 256 bits.  For whatever reason, the current implementation
     * only supports up to 32 bits, as the exponent is passed as a uint32_t
     * through the cavs_op_rsa_verify vector.
     *
     * In future versions, this needs to be a variably sized buffer that gets
     * handled correctly on the remote end, but for now check for overflow
     * defensively and convert the tailing 32-bits as an integer.
     */
    int pre_len = 0;
    ssize_t e_len = (size_t)[testData.eData length];
    uint8_t *e_buf = (uint8_t *)[testData.eData bytes];

    /* Find the first non-0 byte. */
    for (; pre_len < e_len && e_buf[pre_len] == 0; pre_len++) { }
    if ((e_len - pre_len) < 0 || (e_len - pre_len) > sizeof(uint32_t)) {
        errorf("exponent larger than 32-bits supplied, needs support.");
        return NO;
    }

    /* Covert that to a 32-bit big-endian integer. */
    request.exponent = (e_buf[e_len - 4] << 24 |
            e_buf[e_len - 3] << 16 |
            e_buf[e_len - 2] << 8 |
            e_buf[e_len - 1]);

    size_t len = sizeof(uint32_t);
    uint8_t *wksp = NULL;
    int ret = cavs_dispatch(testData.testTarget, request.vector, &request, &wksp, &len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed cavs_dispatch");
        return NO;
    }

    valid = *(uint32_t *)wksp;

out:
    if (testData.printNData) {
        [self outputFormat:@"n = %@", DataToHexString(testData.nData)];
        [self outputString:@""];
    }

    [self outputFormat:@"SHAAlg = %@", CipherTypeToString(testData.shaAlgo)];
    [self outputFormat:@"e = %@", DataToHexString(testData.eData)];
    [self outputFormat:@"Msg = %@", DataToHexString(testData.msg)];
    [self outputFormat:@"S = %@", DataToHexString(testData.sData)];
    [self outputFormat:@"Result = %s", valid ? "PASS" : "FAIL"];
    [self outputString:nil];

    return YES;
}

@end
