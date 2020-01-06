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

#import <Foundation/Foundation.h>

/* ==========================================================================
    Organization of the Dictionary returned from [TestFileParser parse]

    The NIST CAVS test files are not 'normalized' in any consistent way. The
    output of the parse method tries to put the data into a form that can be
    used to do the CAVS test and allow for outputing the appropriate output
    file.

    The [TestFileParser parse] method returns a dictionary.  That dictionary
    records will key keyed by the file name that was parsed.  The value for that
    dictionary will be the File Dictionary.  An example of the top level
    dictionary returned form the [TestFileParser parse] method would be

    [@"CBCGFSbox128.req", FileDictionary],
    [@"CBCGFSbox192.req", FileDictionary],
    [@"CBCGFSbox256.req", FileDictionary],
    ...

    The File dictionary contains information from a specific CAVS test file.
    There are two keys used in a File dictionary.  The TFFileHeaderKey key
    has a value of an Array of header strings from the CAVS test file.  The
    other key is the TFTestGroupKey key which has a value of a dictionary of
    test information.  An example of the File dictionary would be

    [TFFileHeaderKey, [# CAVS 10.1,
                       # Config info for apple-ios5_iphone_sw,
                       # AESVS GFSbox test data for CBC,
                       # State : Encrypt and Decrypt,
                       # Key Length : 256,
                       # Generated on Wed Oct 20 21:44:57 2010]]

    [TFTestGroupKey, TestGroupArray]

    The test group array contains an array of Test Dictionaries.  The order in the array
    will be the order in the file.  Each array item will be a dictionary with the items
    as follows:

    [TFEnvironmentDataKey, [[ENCRYPT]]]

    [TFTestKey, Array(TestFileData)]

*/

FOUNDATION_EXPORT NSString *const
TFFileHeaderKey;        // A key in the File dictionary that contains the file headers
FOUNDATION_EXPORT NSString *const
TFTestGroupKey;         // A key in the File dictionary that contains the Test Group Array
FOUNDATION_EXPORT NSString *const
TFEnvironmentDataKey;   // A key in the Test Group dictionary that contains an array of environment strings
FOUNDATION_EXPORT NSString *const
TFTestKey;              // A Key in the Test Group dictionary that contains an array of TestFileData objects.
FOUNDATION_EXPORT NSString *const
TFImplementationKey;    // A Key in the File dictionary that contains a dictionary of the implementation data
FOUNDATION_EXPORT NSString *const
TFPlatformKey;          // A Key in the Implementation dictionary that specifies the platform i.e. iOS OSX
FOUNDATION_EXPORT NSString *const
TFExecutionSpaceKey;    // A Key in the Implementation dictionary that specifies the execution space i.e. kernel or user
FOUNDATION_EXPORT NSString *const
TFProcessorKey;         // A Key in the Implementation dictionary that specifies the processor A4, A5, i5, i7
FOUNDATION_EXPORT NSString *const
TFTestName;             // A Key in the Implementation dictionary that specifies the test type aesglad, aeshw, shanosse, etc
FOUNDATION_EXPORT NSString *const
TFGroupCountReset;      // A Key in the Implementation dictionary that specifies Count increments reset on group boundaries


/* ==========================================================================
    This class is used to parse CAVS input files
   ========================================================================== */
@interface TestFileParser : NSObject
{
    NSMutableDictionary*    _parseTree;
    NSString*               _parseDirectory;
    BOOL                    _useDSAForSignGenAndSignVer;
    NSString*               _keyString;
    cavs_target             _testTarget;
}

@property (assign) BOOL useDSAForSignGenAndSignVer;
@property (retain) NSString* keyString;
@property (assign) cavs_target testTarget;


- (id)initWithDirectoryPath:(NSString *)path;

// This returns an array of TestFileData objects.
- (NSDictionary*)parse;
@end

enum        // TFTestType
{
    TTUnknownTestType                   = 0,        // Unknown Test Type - Also used as initial default
    TTCipherKnownAnswerTest             = 1,        // Cipher - KAT -- Known Answer Test
    TTCipherMonteCarloTest              = 2,        // Cipher - MCT -- Monte Carlo Test
    TTHashKnownAnswerTest               = 3,        // Hash - KAT -- Known Answer Test
    TTHashMonteCarloTest                = 4,        // Hash - MCT -- Monte Carlo Test
    TTRSASignatureGeneration            = 5,        // RSA - Signature Generation
    TTRSASignatureVerification          = 6,        // RSA - Siganture Verification
    TTRNGKAT                            = 7,        // RNG - KAT - Known Answer Test
    TTRNGMCT                            = 8,        // RNG - MCT - Monte Carlo Test
    TTHMAC                              = 9,        // HMAC
    TTDSAPQGGen                         = 10,       // DSA - PQG Generation
    TTDSASignatureGeneration            = 11,       // DSA - Signature Generation
    TTDSASignatureVerification          = 12,       // DSA - Signature Verification
    TTRSAKeyGeneration                  = 13,       // RSA - Key Generation
    TTDRBG                              = 14,       // AES-DRBG
    TTGCM                               = 15,       // AES-GCM
    TTECKeyGeneration                   = 16,       // EC Key Generation
    TTECSignatureGeneration             = 17,       // EC Signature Generation
    TTECSignatureGenerationComponent    = 18,       // EC Signature Generation Component
    TTECSignatureVerification           = 19,       // EC Signature Verification
    TTECPublicKeyVerification           = 20,       // EC Public Key Verification
    TTXTS                               = 21,       // AES - XTS
    TTAESKeyWrap                        = 22,       // AES - KW - KeyWrap -- SP 800-38F
    TTAESKeyWrapPad                     = 23,       // AES - KWP- KeyWrap with Padding -- SP 800-38F
    TTECDHPrimFuncEphemeralUnified      = 24,       // ECDH Function Test Primitve Z - dhEpehemeralUnified
    TTECDHPrimFuncFullUnified           = 25,       // ECDH Function Test Primitve Z - dhFullUnified
    TTECDHPrimFuncOnePassDH             = 26,       // ECDH Function Test Primitve Z - dhOnePassDH
    TTECDHPrimFuncOnePassDH_KDFConcat   = 27,       // ECDH Function Test Primitve Z - dhOnePassDH with KDF Concatenation
    TTECDHPrimFuncOnePassUnified        = 28,       // ECDH Function Test Primitve Z - dhOnePassUnified
    TTECDHPrimFuncStaticUnified         = 29,       // ECDH Function Test Primitve Z - dhStaticUnified
    TTECDHPrimValEphemeralUnified       = 30,       // ECDH Validity Test Primitve Z - dhEpehemeralUnified
    TTECDHPrimValFullUnified            = 31,       // ECDH Validity Test Primitve Z - dhFullUnified
    TTECDHPrimValOnePassDH              = 32,       // ECDH Validity Test Primitve Z - dhOnePassDH
    TTECDHPrimValOnePassDH_KDFConcat    = 33,       // ECDH Validity Test Primitve Z - dhOnePassDH with KDF Concatenation
    TTECDHPrimValOnePassUnified         = 34,       // ECDH Validity Test Primitve Z - dhOnePassUnified
    TTECDHPrimValStaticUnified          = 35,       // ECDH Validity Test Primitve Z - dhStaticUnified
    TTECDHCurve25519GenerateShared      = 36,       // ECDH Curve25519 Generate Shared Secret Test
    TTECDHCurve25519VerifyShared        = 37,       // ECDH Curve25519 Verify Shared Secret Test
    TTECDHCurve25519KeyVerify           = 38,       // ECDH Curve25519 Key Verification Test
    TTECDHCurve25519KeyGenerate         = 39,       // ECDH Curve25519 Key Generation Test
    TTCCMVADT                           = 40,       // AES-CCM  VADT    -- Variable Associated Data Test
    TTCCMVNT                            = 41,       // AES-CCM  VNT     -- Variable Nonce Test
    TTCCMVPT                            = 42,       // AES-CCM  VPT     -- Variable Payload Test
    TTCCMVTT                            = 43,       // AES-CCM  VTT     -- Variable Tag Test
    TTCCMDVPT                           = 44,       // AES-CCM  DVPT    -- Decryption Verification Process Test
    TTHMACDRBG                          = 45,       // HMAC-DRBG
    TTFIPSPOST                          = 46,       // FIPS POST tests
    TTHKDF                              = 47,       // HKDF
    TTFFDHKeyGenerate                   = 48,       // DH Key Generation - KeyPair.req
    TTFFDHFunction                      = 49,       // DH Functional Test
    TTFFDHValidity                      = 50,       // DH Validity Test
};  typedef NSInteger TFTestType;


enum        // TFModeType
{
    TFModeUnknown                       = 0,
    TFModeCBC                           = 1,
    TFModeECB                           = 2,
    TFModeOFB                           = 3,
    TFModeCFB                           = 4,
    TFModeCFB8                          = 5,
};  typedef NSInteger TFModeType;

enum        // TFCipherType
{
    TFCipherUnknown                     = 0,
    TFCipherSHA1                        = 1,
    TFCipherSHA224                      = 2,
    TFCipherSHA256                      = 3,
    TFCipherSHA384                      = 4,
    TFCipherSHA512                      = 5,
    TFCipherRC4                         = 6,
    TFCipherAES                         = 7,
    TFCipher3DES                        = 8,
    TFCipherDRBG                        = 9,
    TFCipherHMAC                        = 10,
    TFCipherRSA                         = 11,
    TFCipherECC                         = 12,
    TFCipherCurve25519                  = 13,
    TFCiphered25519                     = 14,
    TFCipherSHA3_224                    = 15,       // NYI - Not Yet Implemented
    TFCipherSHA3_256                    = 16,       // NYI - Not Yet Implemented
    TFCipherSHA3_384                    = 17,       // NYI - Not Yet Implemented
    TFCipherSHA3_512                    = 18,       // NYI - Not Yet Implemented
    TFCipherSHAKE128                    = 19,       // NYI - Not Yet Implemented
    TFCipherSHAKE256                    = 20,       // NYI - Not Yet Implemented
};  typedef NSInteger TFCipherType;

enum
{
    TAESIMPLUnknown                     = 0,        // AES Implementation - Unknown / Inital Default
    TAESIMPLNormal                      = 1,        // AES Implementation - V&N groups implementation
    TAESIMPLNonOptimized                = 2,        // AES Implementation - LTC implementation
    TAESIMPLHardware                    = 3,        // AES Implementation - Silicon
};  typedef NSInteger TFAESIMPLType;

enum
{
    TRSASigTypePKCS1_5                  = 0,
    TRSASigTypeX9_31                    = 1,
};  typedef NSInteger TRSASigType;

enum
{
    TRSAKeyGenTypeUnkown                = 0,
    TRSAKeyGenTypeProbPrimeWithCondition= 1,
    TRSAKeyGenTypeRandProbPrime         = 2,
    TRSAKeyGenTypeRandProbPrimeKAT      = 3,       // NYI - Not Yet Implemented
};  typedef NSInteger TRSAKeyGenType;

enum
{
    TECKeyGenTypeUnknown                = 0,
    TECKeyGenTypeRandomBits             = 1,
    TECKeyGenTypeTestingCandidates      = 2,
};  typedef NSInteger TECKeyGenType;


/* ==========================================================================
    This class is used to hold the parsed data for an individual test parsed
    from a CAVS request (.req) file.
   ========================================================================== */
@interface TestFileData : NSObject
{
@public
    TFTestType      _testType;
    TFModeType      _modeType;
    TFCipherType    _cipherType;
    TFCipherType    _ecDigestType;
    BOOL            _encryption;
    BOOL            _monteCarlo;
    BOOL            _predictionResistance;
    BOOL            _singleTDESKey;

    NSArray*        _testEnvironmentData;
    NSData*         _key;
    NSNumber*       _numKeys;
    NSData*         _key2;
    NSData*         _key3;
    NSData*         _tDESKey;
    NSData*         _iv;
    NSData*         _plainText;
    NSNumber*       _length;
    NSData*         _entropyInput;
    NSData*         _nonce;
    NSData*         _personalizationString;

    NSMutableArray* _additionalInput;
    NSMutableArray* _additionalEntropyInput;

    NSNumber*       _klen;
    NSNumber*       _tlen;
    NSNumber*       _plen;
    NSNumber*       _nlen;
    NSNumber*       _alen;
    NSData*         _msg;
    TFCipherType    _shaAlgo;
    NSNumber*       _groupLen;
    NSData*         _groupSeed;
    NSData*         _nData;
    NSData*         _eData;
    NSData*         _sData;
    NSNumber*       _modulus;

    NSData*         _dtData;
    NSData*         _vData;
    NSData*         _capitalNData;
    NSData*         _capitalPData;
    NSData*         _capitalQData;
    NSData*         _capitalGData;
    NSData*         _capitalYData;
    NSData*         _capitalRData;
    NSData*         _xp1;
    NSData*         _xp2;
    NSData*         _xp;
    NSData*         _xq1;
    NSData*         _xq2;
    NSData*         _xq;
    NSData*         _prnd;
    NSData*         _qrnd;

    NSData*         _QeX;
    NSData*         _QeY;
    NSData*         _QsX;
    NSData*         _QsY;
    NSData*         _deIUT;
    NSData*         _QeIUTx;
    NSData*         _QeIUTy;
    NSData*         _dsIUT;
    NSData*         _QsIUTx;
    NSData*         _QsIUTy;
    NSData*         _HashZZ;
    NSData*         _OI;
    NSData*         _CAVSTag;

    NSString*       _resultFieldName;
    NSData*         _result;
    NSNumber*       _rsaKeySize;
    NSNumber*       _ecDigestSize;
    BOOL            _rsaKeySizeChanged;

    NSData*         _aData;
    NSNumber*       _ivLen;
    NSNumber*       _tagLength;
    NSData*         _tag;
    NSString*       _fileName;
    NSNumber*       _nValue;
    NSData*         _qX;
    NSData*         _qY;
    NSNumber*       _curve;
    NSData*         _rData;
    BOOL            _printNData;
    TFAESIMPLType   _aesImplType;
    TRSASigType     _rsaSigType;
    TRSAKeyGenType  _rsaKeyGenType;
    TECKeyGenType   _ecKeyGenType;
    NSNumber*       _dataUnitSeqNumber;
    NSNumber*       _dataUnitLen;

    NSData*         _classBStaticPrivKey;
    NSData*         _classBStaticPubKey;
    NSData*         _classBEphemPrivKey;
    NSData*         _classBEphemPubKey;
    NSData*         _classBSharedSecret;

    NSString*       _keyString;
    cavs_target     _testTarget;

    NSNumber*       _returnedBitsLen;
}

@property (assign) TFTestType       testType;
@property (assign) TFModeType       modeType;
@property (assign) TFCipherType     cipherType;
@property (assign) TFCipherType     ecDigestType;
@property (assign) BOOL             encryption;
@property (assign) BOOL             monteCarlo;
@property (assign) BOOL             predictionResistance;
@property (assign) BOOL             singleTDESKey;
@property (assign) BOOL             rsaKeySizeChanged;

@property (retain) NSData*          key;
@property (retain) NSNumber*        numKeys;
@property (readonly)NSData*         key1;
@property (retain) NSData*          key2;
@property (retain) NSData*          key3;
@property (retain) NSData*          iv;
@property (retain) NSData*          plainText;
@property (retain) NSNumber*        length;
@property (retain) NSData*          entropyInput;
@property (retain) NSData*          nonce;
@property (retain) NSData*          personalizationString;

@property (retain) NSMutableArray*  additionalInput;
@property (retain) NSMutableArray*  additionalEntropyInput;

@property (retain) NSNumber*        klen;
@property (retain) NSNumber*        tlen;
@property (retain) NSNumber*        plen;
@property (retain) NSNumber*        nlen;
@property (retain) NSNumber*        alen;
@property (retain) NSData*          msg;
@property (assign) TFCipherType     shaAlgo;
@property (retain) NSNumber*        groupLen;
@property (retain) NSData*          groupSeed;
@property (retain) NSData*          nData;
@property (retain) NSData*          eData;
@property (retain) NSData*          sData;
@property (retain) NSData*          dtData;
@property (retain) NSData*          vData;
@property (retain) NSData*          capitalNData;
@property (retain) NSData*          capitalPData;
@property (retain) NSData*          capitalQData;
@property (retain) NSData*          capitalGData;
@property (retain) NSData*          capitalYData;
@property (retain) NSData*          capitalRData;
@property (retain) NSData*          xp1;
@property (retain) NSData*          xp2;
@property (retain) NSData*          xp;
@property (retain) NSData*          xq1;
@property (retain) NSData*          xq2;
@property (retain) NSData*          xq;
@property (retain) NSData*          prnd;
@property (retain) NSData*          qrnd;
@property (retain) NSData*          QeX;
@property (retain) NSData*          QeY;
@property (retain) NSData*          QsX;
@property (retain) NSData*          QsY;
@property (retain) NSData*          deIUT;
@property (retain) NSData*          QeIUTx;
@property (retain) NSData*          QeIUTy;
@property (retain) NSData*          dsIUT;
@property (retain) NSData*          QsIUTx;
@property (retain) NSData*          QsIUTy;
@property (retain) NSData*          HashZZ;
@property (retain) NSData*          CAVSTag;
@property (retain) NSData*          OI;
@property (retain) NSString*        resultFieldName;
@property (retain) NSData*          result;
@property (readonly) NSString*      testName;
@property (retain) NSNumber*        rsaKeySize;
@property (retain) NSNumber*        ecDigestSize;
@property (retain) NSData*          aData;
@property (retain) NSNumber*        ivLen;
@property (retain) NSNumber*        tagLength;
@property (retain) NSData*          tag;
@property (retain) NSString*        fileName;
@property (retain) NSNumber*        nValue;
@property (retain) NSData*          qX;
@property (retain) NSData*          qY;
@property (retain) NSNumber*        curve;
@property (assign) BOOL             printNData;
@property (assign) TFAESIMPLType    aesImplType;
@property (assign) TRSASigType      rsaSigType;
@property (assign) TRSAKeyGenType   rsaKeyGenType;
@property (assign) TECKeyGenType    ecKeyGenType;
@property (retain) NSNumber*        dataUnitSeqNumber;
@property (retain) NSNumber*        dataUnitLen;

@property (retain) NSData*          classBStaticPrivKey;
@property (retain) NSData*          classBStaticPubKey;
@property (retain) NSData*          classBEphemPrivKey;
@property (retain) NSData*          classBEphemPubKey;
@property (retain) NSData*          classBSharedSecret;

@property (retain) NSString*        keyString;
@property (assign) cavs_target      testTarget;

@property (retain) NSNumber*        returnedBitsLen;

- (void)print:(NSFileHandle *)      fileHandle;


@end


@interface NSString (PrivateRegExExtension)

- (BOOL)isMatchedByRegex:(NSString*)regex;
// This assumes only a single capture group
- (NSString *)stringMatchedByRegex:(NSString*)regex;
- (NSString *)stringMatchedWithMultipleRegexs:(NSArray *)regex_strs;
@end

