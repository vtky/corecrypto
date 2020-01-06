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

#include <stdlib.h>
#include <corecrypto/cc_config.h>

#include "cavs_common.h"

#import "testbyteBuffer.h"

#import "CavsMemoryHelpers.h"
#import "CavsTestFileParser.h"
#import "CavsTestDispatcher.h"

NSString *const TFFileHeaderKey         = @"TFFileHeaderKey";
NSString *const TFTestGroupKey          = @"TFTestGroupKey";
NSString *const TFEnvironmentDataKey    = @"TFEnvironmentDataKey";
NSString *const TFTestKey               = @"TFTestKey";
NSString *const TFImplementationKey     = @"TFImplementationKey";
NSString *const TFPlatformKey           = @"TFPlatformKey";
NSString *const TFExecutionSpaceKey     = @"TFExecutionSpaceKey";
NSString *const TFProcessorKey          = @"TFProcessorKey";
NSString *const TFTestName              = @"TFTestName";
NSString *const TFGroupCountReset       = @"TFGroupCountReset";


/* --------------------------------------------------------------------------
    Local Function prototypes
 -------------------------------------------------------------------------- */
NSString*   ModeTypeToString(TFModeType mode);
NSData*     HexStringToData(NSString* hexString);
NSString*   DataToHexString(NSData* data);
NSString*   BufToHexString(uint8_t* data, size_t len);


/* --------------------------------------------------------------------------
    Function:       ModeTypeToString
    Description:    A helper function to get a string name for a mode type
 -------------------------------------------------------------------------- */
NSString* ModeTypeToString(TFModeType mode)
{
    NSString* result = nil;

    switch(mode)
    {
        default:
        case TFModeUnknown: result = @"Unknown";    break;
        case TFModeCBC:     result = @"CBC";        break;
        case TFModeECB:     result = @"ECB";        break;
        case TFModeOFB:     result = @"OFB";        break;
        case TFModeCFB:     result = @"CFB";        break;
        case TFModeCFB8:    result = @"CFB8";       break;
    }
    return result;
}

/* --------------------------------------------------------------------------
    Function:       HexStringToData
    Description:    A helper function to convert a Hex string into data
 -------------------------------------------------------------------------- */
NSData* HexStringToData(NSString* hexString)
{
    NSData* result = nil;
    if (nil == hexString)   return result;

    byteBuffer
    buffer = hexStringToBytes((char *)[hexString UTF8String]);
    if (NULL == buffer || 0 == buffer->len || NULL == buffer->bytes)
        return result;

    result = [NSData dataWithBytes:buffer->bytes
                            length:buffer->len];

    free(buffer);
    return result;
}

/* --------------------------------------------------------------------------
    Function:       DataToHexString
    Description:    A helper function to convert data into a Hex String
 -------------------------------------------------------------------------- */
NSString* DataToHexString(NSData* data)
{
    NSString* result = nil;
    if (nil == data)    return @"";

    byteBufferStruct bufStruct;
    bufStruct.len   = [data length];
    bufStruct.bytes = (uint8_t*)[data bytes];

    char* buffer  = bytesToHexString(&bufStruct);
    result  = [NSString stringWithUTF8String:buffer];
    free(buffer);
    return result;
}


/* --------------------------------------------------------------------------
    Function:       BufToHexString
    Description:    A helper function to convert data into a Hex String
 -------------------------------------------------------------------------- */
NSString* BufToHexString(uint8_t* data, size_t len)
{
    NSString* result = nil;
    if (data == nil)  return @"";

    byteBufferStruct bufStruct;
    bufStruct.len   = len;
    bufStruct.bytes = data;

    char* buffer    = bytesToHexString(&bufStruct);
    result          = [NSString stringWithUTF8String:buffer];
    free(buffer);
    return result;
}

/* ==========================================================================
    Implementation TestFileData
 ========================================================================== */
@implementation TestFileData

/* --------------------------------------------------------------------------
    Provide standarized ivar methods
 -------------------------------------------------------------------------- */
@synthesize testType                = _testType;
@synthesize modeType                = _modeType;
@synthesize cipherType              = _cipherType;
@synthesize ecDigestType            = _ecDigestType;
@synthesize encryption              = _encryption;
@synthesize monteCarlo              = _monteCarlo;
@synthesize predictionResistance    = _predictionResistance;
@synthesize singleTDESKey           = _singleTDESKey;
@synthesize rsaKeySizeChanged       = _rsaKeySizeChanged;
@dynamic    key;
@synthesize numKeys                 = _numKeys;
@dynamic    key1;
@synthesize key2                    = _key2;
@synthesize key3                    = _key3;
@synthesize iv                      = _iv;
@synthesize plainText               = _plainText;
@synthesize length                  = _length;
@synthesize entropyInput            = _entropyInput;
@synthesize nonce                   = _nonce;
@synthesize personalizationString   = _personalizationString;
@synthesize additionalInput         = _additionalInput;
@synthesize additionalEntropyInput  = _additionalEntropyInput;

@synthesize klen                    = _klen;
@synthesize tlen                    = _tlen;
@synthesize plen                    = _plen;
@synthesize nlen                    = _nlen;
@synthesize alen                    = _alen;
@synthesize msg                     = _msg;
@synthesize shaAlgo                 = _shaAlgo;
@synthesize groupLen                = _groupLen;
@synthesize groupSeed               = _groupSeed;
@synthesize nData                   = _nData;
@synthesize eData                   = _eData;
@synthesize sData                   = _sData;
@synthesize dtData                  = _dtData;
@synthesize vData                   = _vData;
@synthesize capitalNData            = _capitalNData;
@synthesize capitalPData            = _capitalPData;
@synthesize capitalQData            = _capitalQData;
@synthesize capitalGData            = _capitalGData;
@synthesize capitalYData            = _capitalYData;
@synthesize capitalRData            = _capitalRData;
@synthesize xp                      = _xp;
@synthesize xp1                     = _xp1;
@synthesize xp2                     = _xp2;
@synthesize xq                      = _xq;
@synthesize xq1                     = _xq1;
@synthesize xq2                     = _xq2;
@synthesize prnd                    = _prnd;
@synthesize qrnd                    = _qrnd;

@synthesize QeX                     = _QeX;
@synthesize QeY                     = _QeY;
@synthesize QsX                     = _QsX;
@synthesize QsY                     = _QsY;
@synthesize deIUT                   = _deIUT;
@synthesize QeIUTx                  = _QeIUTx;
@synthesize QeIUTy                  = _QeIUTy;
@synthesize dsIUT                   = _dsIUT;
@synthesize QsIUTx                  = _QsIUTx;
@synthesize QsIUTy                  = _QsIUTy;
@synthesize HashZZ                  = _HashZZ;
@synthesize CAVSTag                 = _CAVSTag;
@synthesize OI                      = _OI;

@synthesize resultFieldName         = _resultFieldName;
@synthesize result                  = _result;
@dynamic    testName;
@synthesize rsaKeySize              = _rsaKeySize;
@synthesize ecDigestSize            = _ecDigestSize;
@synthesize aData                   = _aData;
@synthesize ivLen                   = _ivLen;
@synthesize tagLength               = _tagLength;
@synthesize tag                     = _tag;
@synthesize fileName                = _fileName;
@synthesize nValue                  = _nValue;
@synthesize qX                      = _qX;
@synthesize qY                      = _qY;
@synthesize curve                   = _curve;
@synthesize printNData              = _printNData;
@synthesize aesImplType             = _aesImplType;
@synthesize rsaSigType              = _rsaSigType;
@synthesize rsaKeyGenType           = _rsaKeyGenType;
@synthesize ecKeyGenType            = _ecKeyGenType;
@synthesize dataUnitSeqNumber       = _dataUnitSeqNumber;
@synthesize dataUnitLen             = _dataUnitLen;

@synthesize classBStaticPrivKey     = _classBStaticPrivKey;
@synthesize classBStaticPubKey      = _classBStaticPubKey;
@synthesize classBEphemPrivKey      = _classBEphemPrivKey;
@synthesize classBEphemPubKey       = _classBEphemPubKey;
@synthesize classBSharedSecret      = _classBSharedSecret;

@synthesize keyString               = _keyString;
@synthesize testTarget              = _testTarget;

@synthesize returnedBitsLen         = _returnedBitsLen;

/* --------------------------------------------------------------------------
    Method:         init
    Description:    Standard Object initialized
 -------------------------------------------------------------------------- */
- (id)init
{
    if ((self = [super init]))
    {
        _testEnvironmentData    = nil;
        _key                    = nil;
        _key2                   = nil;
        _key3                   = nil;
        _tDESKey                = nil;
        _iv                     = nil;
        _plainText              = nil;
        _length                 = nil;
        _entropyInput           = nil;
        _nonce                  = nil;
        _personalizationString  = nil;
        _klen                   = nil;
        _tlen                   = nil;
        _plen                   = nil;
        _nlen                   = nil;
        _alen                   = nil;
        _msg                    = nil;
        _groupLen               = nil;
        _groupSeed              = nil;
        _nData                  = nil;
        _eData                  = nil;
        _sData                  = nil;
        _dtData                 = nil;
        _vData                  = nil;
        _capitalNData           = nil;
        _capitalPData           = nil;
        _capitalQData           = nil;
        _capitalGData           = nil;
        _capitalYData           = nil;
        _capitalRData           = nil;
        _xp1                    = nil;
        _xp2                    = nil;
        _xp                     = nil;
        _xq1                    = nil;
        _xq2                    = nil;
        _xq                     = nil;
        _prnd                   = nil;
        _qrnd                   = nil;
        _QeX                    = nil;
        _QeY                    = nil;
        _QsX                    = nil;
        _QsY                    = nil;
        _deIUT                  = nil;
        _QeIUTx                 = nil;
        _QeIUTy                 = nil;
        _dsIUT                  = nil;
        _QsIUTx                 = nil;
        _QsIUTy                 = nil;
        _HashZZ                 = nil;
        _CAVSTag                = nil;
        _OI                     = nil;

        _resultFieldName        = nil;
        _result                 = nil;
        _singleTDESKey          = NO;
        _rsaKeySize             = nil;
        _rsaKeySizeChanged      = NO;
        _aData                  = nil;
        _ivLen                  = nil;
        _tagLength              = nil;
        _tag                    = nil;
        _fileName               = nil;
        _nValue                 = nil;
        _qX                     = nil;
        _qY                     = nil;
        _curve                  = nil;
        _printNData             = NO;
        _aesImplType            = TAESIMPLUnknown;
        _rsaSigType             = TRSASigTypePKCS1_5;
        _rsaKeyGenType          = TRSAKeyGenTypeProbPrimeWithCondition;
        _ecKeyGenType           = TECKeyGenTypeUnknown;
        _ecDigestType           = 0;
        _dataUnitSeqNumber      = nil;
        _dataUnitLen            = nil;
        _classBStaticPrivKey    = nil;
        _classBStaticPubKey     = nil;
        _classBEphemPrivKey     = nil;
        _classBEphemPubKey      = nil;
        _classBSharedSecret     = nil;
        _returnedBitsLen        = nil;

    }
    return self;
}

/* --------------------------------------------------------------------------
    Method:         dealloc
    Description:    Standard object memory reclaimation routine
 -------------------------------------------------------------------------- */
- (void)dealloc
{
    [_testEnvironmentData release];
    [_key release];
    [_key2 release];
    [_key3 release];
    [_tDESKey release];
    [_iv release];
    [_plainText release];
    [_length release];
    [_entropyInput release];
    [_nonce release];
    [_personalizationString release];
    [_klen release];
    [_tlen release];
    [_plen release];
    [_nlen release];
    [_alen release];
    [_msg release];
    [_groupLen release];
    [_groupSeed release];
    [_nData release];
    [_eData release];
    [_sData release];
    [_dtData release];
    [_vData release];
    [_capitalNData release];
    [_capitalPData release];
    [_capitalQData release];
    [_capitalGData release];
    [_capitalYData release];
    [_capitalRData release];
    [_xp1 release];
    [_xp2 release];
    [_xp release];
    [_xq1 release];
    [_xq2 release];
    [_xq release];
    [_prnd release];
    [_qrnd release];
    [_QeX release];
    [_QeY release];
    [_QsX release];
    [_QsY release];
    [_deIUT release];
    [_QeIUTx release];
    [_QeIUTy release];
    [_dsIUT release];
    [_QsIUTx release];
    [_QsIUTy release];
    [_HashZZ release];
    [_CAVSTag release];
    [_OI release];
    [_resultFieldName release];
    [_result release];
    [_rsaKeySize release];
    [_aData release];
    [_ivLen release];
    [_tagLength release];
    [_tag release];
    [_fileName release];
    [_nValue release];
    [_qX release];
    [_qY release];
    [_curve release];
    [_dataUnitSeqNumber release];
    [_dataUnitLen release];
    [_classBStaticPrivKey release];
    [_classBStaticPubKey release];
    [_classBEphemPrivKey release];
    [_classBEphemPubKey release];
    [_classBSharedSecret release];


    [_keyString release];

    [_returnedBitsLen release];

    [super dealloc];
}

/* --------------------------------------------------------------------------
    Method:         key
    Description:    Return the key property
 -------------------------------------------------------------------------- */
- (NSData *)key
{
    // If this is NOT a TDES cipher then just return the _key value;
    if (TFCipher3DES != self.cipherType)    return _key;

    // This is a TDES cipher.  Look to see if the tDESKey has been
    // set if so just return that
    if (nil != _tDESKey)    return _tDESKey;

    // The tDESKey has NOT been set so compute it now.
    NSMutableData*
    tempKey =   [NSMutableData data];
                [tempKey appendData:_key];
                [tempKey appendData:_key2];
                [tempKey appendData:_key3];

    _tDESKey = [[NSData alloc] initWithData:tempKey];

    return _tDESKey;
}


/* --------------------------------------------------------------------------
    Method:         setKey:
    Description:    Set the key property
 -------------------------------------------------------------------------- */
- (void)setKey:(NSData *)key
{
    NSData* tempKey = [key retain];
    [_key release];
    _key = tempKey;

    if (TFCipher3DES == self.cipherType)
    {
        [_tDESKey release];

        NSMutableData*
        tempKey =   [NSMutableData data];
                    [tempKey appendData:_key];
                    [tempKey appendData:_key2];
                    [tempKey appendData:_key3];

        _tDESKey =  [[NSData alloc] initWithData:tempKey];
    }
}

/* --------------------------------------------------------------------------
    Method:         key1
    Description:    return the TDES key1 value
 -------------------------------------------------------------------------- */
- (NSData *)key1
{
    if (TFCipher3DES != self.cipherType)
        return nil;

    return _key;
}

/* --------------------------------------------------------------------------
    Method:         testName
    Description:    return the testname as a string
 -------------------------------------------------------------------------- */
- (NSString *)testName
{
    NSString* cipherName    = CipherTypeToString(_cipherType);
    NSString* modeName      = ModeTypeToString(_modeType);
    NSString* keyLengthStr  = nil;
    if (nil != _key)
    {
#if defined(__x86_64__) || defined(__arm64__)
    keyLengthStr = [NSString stringWithFormat:@"%lu",[_key length]];
#else
    keyLengthStr = [NSString stringWithFormat:@"%u",[_key length]];
#endif
    }

    NSString*
    resultStr = [NSString stringWithFormat:@"%@ %@ %@", cipherName, modeName, keyLengthStr];

    return resultStr;
}

/* --------------------------------------------------------------------------
    Method:         print
    Description:    print current dataset to output file
 -------------------------------------------------------------------------- */
- (void)print:(NSFileHandle *)fileHandle
{
    NSAutoreleasePool* pool = [NSAutoreleasePool new];
    NSString* tempStr   = nil;
    NSString* printStr  = nil;
    NSString* crStr     = @"\n";

    if (TFCipher3DES == self.cipherType)
    {
        if (self.singleTDESKey)             // Single TDES Key
        {
            tempStr =  DataToHexString(_key);
            printStr = [NSString stringWithFormat:@"KEYs = %@",tempStr];
            if (nil != fileHandle)
            {
                [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
            }
        }
        else                                // Three TDES Keys
        {
            tempStr =  DataToHexString(_key);
            printStr = [NSString stringWithFormat:@"KEY1 = %@",tempStr];
            if (nil != fileHandle)
            {
                [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
            }

            tempStr =  DataToHexString(_key2);
            printStr = [NSString stringWithFormat:@"KEY2 = %@",tempStr];
            if (nil != fileHandle)
            {
                [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
            }

            tempStr =  DataToHexString(_key3);
            printStr = [NSString stringWithFormat:@"KEY3 = %@",tempStr];
            if (nil != fileHandle)
            {
                [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
            }
        }
    }
    else
    {
        if (nil != _key)
        {
            tempStr =  DataToHexString(_key);
            printStr = [NSString stringWithFormat:@"KEY = %@",tempStr];
            if (nil != fileHandle)
            {
                [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
            }
        }
    }

    if (nil != _iv)
    {
        tempStr =  DataToHexString(_iv);
        printStr = [NSString stringWithFormat:@"IV = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _plainText)
    {
        tempStr =  DataToHexString(_plainText);
        printStr = [NSString stringWithFormat:@"%@ = %@",((_encryption) ? @"PLAINTEXT" : @"CIPHERTEXT"), tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _length)
    {
        printStr = [NSString stringWithFormat:@"LEN = %d",[_length intValue]];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _entropyInput)
    {
        tempStr =  DataToHexString(_entropyInput);
        printStr = [NSString stringWithFormat:@"EntropyInput = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _nonce || _testType == TTDRBG)
    {
        tempStr =  DataToHexString(_nonce);
        printStr = [NSString stringWithFormat:@"Nonce = %@", _nonce ? tempStr : @""];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _personalizationString)
    {
        if (0 == [_personalizationString length])
        {
            printStr = [NSString stringWithFormat:@"PersonalizationString = "];
        }
        else
        {
            tempStr =  DataToHexString(_personalizationString);
            printStr = [NSString stringWithFormat:@"PersonalizationString = %@",tempStr];
        }

        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _additionalInput && nil != _additionalEntropyInput)
    {
        NSData* tempData = nil;
        if (_predictionResistance)
        {
            tempData = [_additionalInput objectAtIndex:0];
            if (0 == [tempData length])
            {
                printStr = [NSString stringWithFormat:@"AdditionalInput = "];
            }
            else
            {
                tempStr =  DataToHexString(tempData);
                printStr = [NSString stringWithFormat:@"AdditionalInput = %@",tempStr];
            }

            if (nil != fileHandle)
            {
                [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
            }

            tempData = [_additionalEntropyInput objectAtIndex:0];
            if (0 == [tempData length])
            {
                printStr = [NSString stringWithFormat:@"EntropyInputPR = "];
            }
            else
            {
                tempStr =  DataToHexString(tempData);
                printStr = [NSString stringWithFormat:@"EntropyInputPR = %@",tempStr];
            }
            if (nil != fileHandle)
            {
                [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
            }

            tempData = [_additionalInput objectAtIndex:1];
            if (0 == [tempData length])
            {
                printStr = [NSString stringWithFormat:@"AdditionalInput = "];
            }
            else
            {
                tempStr =  DataToHexString(tempData);
                printStr = [NSString stringWithFormat:@"AdditionalInput = %@",tempStr];
            }

            if (nil != fileHandle)
            {
                [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
            }

            tempData = [_additionalEntropyInput objectAtIndex:1];
            if (0 == [tempData length])
            {
                printStr = [NSString stringWithFormat:@"EntropyInputPR = "];
            }
            else
            {
                tempStr =  DataToHexString(tempData);
                printStr = [NSString stringWithFormat:@"EntropyInputPR = %@",tempStr];
            }

            if (nil != fileHandle)
            {
                [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
            }
        }
        else
        {
            if (TTHMACDRBG != _testType) {
                tempData = [_additionalInput objectAtIndex:0];
                if (0 == [tempData length])
                {
                    printStr = [NSString stringWithFormat:@"AdditionalInput = "];
                }
                else
                {
                    tempStr =  DataToHexString(tempData);
                    printStr = [NSString stringWithFormat:@"AdditionalInput = %@",tempStr];
                }

                if (nil != fileHandle)
                {
                    [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                    [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
                }
            }

            tempData = [_additionalEntropyInput objectAtIndex:0];
            if (0 == [tempData length])
            {
                printStr = [NSString stringWithFormat:@"EntropyInputReseed = "];
            }
            else
            {
                tempStr =  DataToHexString(tempData);
                printStr = [NSString stringWithFormat:@"EntropyInputReseed = %@",tempStr];
            }

            if (nil != fileHandle)
            {
                [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
            }

            tempData = [_additionalEntropyInput objectAtIndex:1];
            if (0 == [tempData length])
            {
                printStr = [NSString stringWithFormat:@"AdditionalInputReseed = "];
            }
            else
            {
                tempStr =  DataToHexString(tempData);
                printStr = [NSString stringWithFormat:@"AdditionalInputReseed = %@",tempStr];
            }

            if (nil != fileHandle)
            {
                [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
            }

            if (TTHMACDRBG == _testType) {
                tempData = [_additionalInput objectAtIndex:0];
                if (0 == [tempData length])
                {
                    printStr = [NSString stringWithFormat:@"AdditionalInput = "];
                }
                else
                {
                    tempStr =  DataToHexString(tempData);
                    printStr = [NSString stringWithFormat:@"AdditionalInput = %@",tempStr];
                }
                if (nil != fileHandle)
                {
                    [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                    [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
                }
            }

            tempData = [_additionalInput objectAtIndex:1];
            if (0 == [tempData length])
            {
                printStr = [NSString stringWithFormat:@"AdditionalInput = "];
            }
            else
            {
                tempStr =  DataToHexString(tempData);
                printStr = [NSString stringWithFormat:@"AdditionalInput = %@",tempStr];
            }

            if (nil != fileHandle)
            {
                [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
                [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
            }
        }
    } else {
        if (TTHMACDRBG == _testType) {
            printStr = [NSString stringWithFormat:@"AdditionalInput = "];
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }
    }

    if (nil != _klen)
    {
        NSInteger tempValue = [_klen integerValue];
#if defined(__x86_64__) || defined(__arm64__)
        printStr = [NSString stringWithFormat:@"klen = %ld",tempValue];
#else
        printStr = [NSString stringWithFormat:@"klen = %d",tempValue];
#endif
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _tlen)
    {
        NSInteger tempValue = [_tlen integerValue];
        printStr = [NSString stringWithFormat:@"tlen = %d",(int)tempValue];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _eData)
    {
        tempStr =  DataToHexString(_eData);
        printStr = [NSString stringWithFormat:@"e = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (TFCipherUnknown != _shaAlgo)
    {
        if (_rsaKeySizeChanged)
        {
            // Need to print out the modulus and exponent
            ; // NYI

        }
        printStr = [NSString stringWithFormat:@"SHAAlg = %@", CipherTypeToString(_shaAlgo)];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _msg)
    {
        tempStr =  DataToHexString(_msg);
        printStr = [NSString stringWithFormat:@"MSG = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }


    if (nil != _groupSeed)
    {
        tempStr =  DataToHexString(_groupSeed);
        printStr = [NSString stringWithFormat:@"groupSeed = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _nData)
    {
        tempStr =  DataToHexString(_nData);
        printStr = [NSString stringWithFormat:@"n = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _sData)
    {
        tempStr =  DataToHexString(_sData);
        printStr = [NSString stringWithFormat:@"S = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }

    if (nil != _dtData)
    {
        tempStr =  DataToHexString(_dtData);
        printStr = [NSString stringWithFormat:@"dt = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _vData)
    {
        tempStr =  DataToHexString(_vData);
        printStr = [NSString stringWithFormat:@"v = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _capitalNData)
    {
        tempStr =  DataToHexString(_capitalNData);
        printStr = [NSString stringWithFormat:@"N = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _capitalPData)
    {
        tempStr =  DataToHexString(_capitalPData);
        printStr = [NSString stringWithFormat:@"P = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _capitalQData)
    {
        tempStr =  DataToHexString(_capitalQData);
        printStr = [NSString stringWithFormat:@"Q = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _capitalGData)
    {
        tempStr =  DataToHexString(_capitalGData);
        printStr = [NSString stringWithFormat:@"G = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _capitalYData)
    {
        tempStr =  DataToHexString(_capitalYData);
        printStr = [NSString stringWithFormat:@"Y = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _capitalRData)
    {
        tempStr =  DataToHexString(_capitalRData);
        printStr = [NSString stringWithFormat:@"R = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _xp1)
    {
        tempStr =  DataToHexString(_xp1);
        printStr = [NSString stringWithFormat:@"xp1 = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _xp2)
    {
        tempStr =  DataToHexString(_xp2);
        printStr = [NSString stringWithFormat:@"xp2 = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _xp)
    {
        tempStr =  DataToHexString(_xp);
        printStr = [NSString stringWithFormat:@"xp = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _xq1)
    {
        tempStr =  DataToHexString(_xq1);
        printStr = [NSString stringWithFormat:@"xq1 = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _xq2)
    {
        tempStr =  DataToHexString(_xq2);
        printStr = [NSString stringWithFormat:@"xq2 = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _xq)
    {
        tempStr =  DataToHexString(_xq);
        printStr = [NSString stringWithFormat:@"xq = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _prnd)
    {
        tempStr =  DataToHexString(_prnd);
        printStr = [NSString stringWithFormat:@"prandom = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    if (nil != _qrnd)
    {
        tempStr =  DataToHexString(_qrnd);
        printStr = [NSString stringWithFormat:@"qrandom = %@",tempStr];
        if (nil != fileHandle)
        {
            [fileHandle writeData:[printStr dataUsingEncoding:NSUTF8StringEncoding]];
            [fileHandle writeData:[crStr    dataUsingEncoding:NSUTF8StringEncoding]];
        }

    }
    [pool drain];
}

@end


@implementation NSString (PrivateRegExExtension)

/* --------------------------------------------------------------------------
    Method:         isMatchedByRegex
    Description:
 -------------------------------------------------------------------------- */
- (BOOL)isMatchedByRegex:(NSString*)regex
{
    BOOL result             = NO;
    NSError* error          = nil;
    NSAutoreleasePool* pool = [NSAutoreleasePool new];

    {
        NSRegularExpression* regx = [NSRegularExpression regularExpressionWithPattern:regex
                                                                              options:0
                                                                                error:&error];
        if (nil != error)
        {
            fprintf(stderr, "%s\n", [[NSString stringWithFormat:@"could not create the regular expression %@", regex] UTF8String]);
            [pool drain];
            return result;
        }
        result = (([regx numberOfMatchesInString:self
                                         options:0
                                           range:NSMakeRange(0, [self length])]) > 0);
    }
    [pool drain];
    return result;
}


/* --------------------------------------------------------------------------
    Method:         stringMatchedByRegex
    Description:
 -------------------------------------------------------------------------- */
- (NSString*)stringMatchedByRegex:(NSString*)regex
{
    NSString* result        = nil;
    NSError* error          = nil;
    NSAutoreleasePool* pool = [NSAutoreleasePool new];

    {
        NSRegularExpression* regx = [NSRegularExpression regularExpressionWithPattern:regex
                                                                              options:0
                                                                                error:&error];
        if (nil != error)
        {
            fprintf(stderr, "%s\n", [[NSString stringWithFormat:@"could not create the regular expression %@", regex] UTF8String]);
            [pool drain];
            return result;
        }

        NSArray* matches = [regx matchesInString:self
                                         options:0
                                           range:NSMakeRange(0, [self length])];

        for(NSTextCheckingResult* match in matches)
        {
            NSRange
            matchRange  = [match rangeAtIndex:1];
            result      = [NSString stringWithString:[self substringWithRange:matchRange]];
        }
    }
    [pool drain];
    return result;
}

/* --------------------------------------------------------------------------
    Method:         stringMatchedWithMultipleRegexs
    Description:
 -------------------------------------------------------------------------- */
- (NSString *)stringMatchedWithMultipleRegexs:(NSArray *)regex_strs
{
    NSString* result = nil;
    NSAutoreleasePool* pool = [NSAutoreleasePool new];

    {
        for (NSString* regex in regex_strs)
        {
            result = [self stringMatchedByRegex:regex];
            if (nil != result)
            {
                [pool drain];
                return result;
            }
        }
    }
    [pool drain];
    return result;
}

@end


@interface TestFileParser (PrivateMethods)

- (NSDictionary *)parseLines:(NSArray *)lines fileName:(NSString *)fileName;
- (NSString*)getValueFromKeyValuePairString:(NSString *)aLine;

@end


@implementation TestFileParser

@synthesize useDSAForSignGenAndSignVer  = _useDSAForSignGenAndSignVer;
@synthesize keyString                   = _keyString;
@synthesize testTarget                  = _testTarget;

/* --------------------------------------------------------------------------
    Method:         getValueFromKeyValuePairString:(NSString *)aLine
    Description:    Get the Value from the Key/Value pair within the line (string)
 -------------------------------------------------------------------------- */
- (NSString*)getValueFromKeyValuePairString:(NSString *)aLine
{
    NSString* result    = nil;
    NSString* tempStr   = [aLine stringByTrimmingCharactersInSet:
                           [NSCharacterSet whitespaceAndNewlineCharacterSet]];

    NSArray* components = nil;
    components = [tempStr componentsSeparatedByString:@"="];
    if (nil != components && [components count] > 1)
    {
        result = [[components objectAtIndex:1] stringByTrimmingCharactersInSet:
                  [NSCharacterSet whitespaceAndNewlineCharacterSet]];
    }

    return result;
}


/* --------------------------------------------------------------------------
    Method:         initWithDirectoryPath:(NSString *)path
    Description:    Initial a new instance of a TestFileParser.  The path
                    needs to be a directory that contains the test files
                    to be parsed
 -------------------------------------------------------------------------- */
- (id)initWithDirectoryPath:(NSString *)path
{
    if ((self = [super init]))
    {
        _parseTree      = [NSMutableDictionary new];
        _parseDirectory = [path copy];
        _keyString      = nil;
    }
    return self;
}


/* --------------------------------------------------------------------------
    Method:         dealloc
    Description:    Standard Object memory reclaimation method
 -------------------------------------------------------------------------- */
- (void)dealloc
{
    [_parseTree release];
    [_parseDirectory release];
    [_keyString release];
    [super dealloc];
}


/* --------------------------------------------------------------------------
    Method:         parseLines:(NSArray *)lines fileName:(NSString *)fileName
    Description:    Given an array of lines of a test file create all of the
                    TestFileData ojects that represent a single test from
                    the file and return the File Dictionary
    TODO:           Rewrite this method as a separate target to parse all CMVP
                    vector file types and produce "normalized" test files.
 -------------------------------------------------------------------------- */
- (NSDictionary *)parseLines:(NSArray *)lines
                    fileName:(NSString *)fileName
{
    NSDictionary*       result  = nil;
    NSAutoreleasePool*  pool    = [NSAutoreleasePool new];

    {
        if (nil == lines) {
            [pool drain];
            return result;
        }

        CAVSTestDispatcher*
        dispatcher = [CAVSTestDispatcher currentTestDispatcher];

        if (dispatcher.verbose)
            printf("[TestFileParser][parseLines] Processing file [%s]\n", [fileName UTF8String]);

        NSMutableDictionary*    tempFileDictionary      = [NSMutableDictionary dictionary];
        NSMutableArray*         tempTestGroupArray      = [NSMutableArray array];

        NSMutableArray*         tempTestItems           = [NSMutableArray array];
        NSMutableArray*         tempTestEnvironItems    = [NSMutableArray array];
        NSMutableDictionary*    tempTestGroupDictionary = [NSMutableDictionary dictionary];
        NSMutableArray*         fileHeaderStrings       = [NSMutableArray array];

        TFTestType      testType            = TTUnknownTestType;
        TFModeType      modeType            = TFModeUnknown;
        TFCipherType    cipherType          = TFCipherUnknown;
        TFCipherType    ecDigestType        = TFCipherUnknown;
        NSData*         iv                  = nil;
        NSData*         key                 = nil;
        NSData*         key2                = nil;
        NSData*         key3                = nil;
        BOOL            encryption          = YES;
        BOOL            predictionResistance = NO;

        NSData*         plainText           = nil;
        NSData*         msg                 = nil;
        NSNumber*       length              = nil;
        NSNumber*       klen                = nil;
        NSNumber*       tlen                = nil;
        NSNumber*       plen                = nil;
        NSNumber*       nlen                = nil;
        NSNumber*       alen                = nil;
        NSString*       shaAlgo             = nil;
        NSData*         nData               = nil;
        NSData*         eData               = nil;
        NSData*         sData               = nil;

        NSData*         dtData              = nil;
        NSData*         vData               = nil;
        NSData*         capitalNData        = nil;
        NSData*         capitalPData        = nil;
        NSData*         capitalQData        = nil;
        NSData*         capitalGData        = nil;
        NSData*         capitalYData        = nil;
        NSData*         capitalRData        = nil;
        NSData*         xp1                 = nil;
        NSData*         xp2                 = nil;
        NSData*         xp                  = nil;
        NSData*         xq1                 = nil;
        NSData*         xq2                 = nil;
        NSData*         xq                  = nil;
        NSData*         prnd                = nil;
        NSData*         qrnd                = nil;

        NSData*         QeX                 = nil;
        NSData*         QeY                 = nil;
        NSData*         QsX                 = nil;
        NSData*         QsY                 = nil;
        NSData*         deIUT               = nil;
        NSData*         QeIUTx              = nil;
        NSData*         QeIUTy              = nil;
        NSData*         dsIUT               = nil;
        NSData*         QsIUTx              = nil;
        NSData*         QsIUTy              = nil;
        NSData*         HashZZ              = nil;
        NSData*         CAVSTag             = nil;
        NSData*         OI                  = nil;

        NSString*       tempStr             = nil;
        BOOL            testFound           = NO;
        BOOL            isAMonteCarloTest   = NO;
        BOOL            singleTDESKey       = NO;
        NSNumber*       numKeysValue        = nil;

        NSData*         entropyInput        = nil;
        NSData*         nonce               = nil;
        NSData*         personalizationString  = nil;

        NSMutableArray* additionalInput     = nil;
        NSMutableArray* additionalEntropyInput  = nil;
        NSMutableString* lineEndingStr      = nil;
        NSNumber*       rsaKeySize          = nil;

        NSData*         aData               = nil;
        NSNumber*       ivLen               = nil;
        NSNumber*       tagLength           = nil;
        NSData*         tagData             = nil;
        NSNumber*       ptLength            = nil;
        NSNumber*       aadLength           = nil;
        NSNumber*       nValue              = nil;
        NSData*         qX                  = nil;
        NSData*         qY                  = nil;
        NSNumber*       curve               = nil;
        BOOL            nDataSeen           = NO;
        TFAESIMPLType   aesImplType         = TAESIMPLUnknown;
        TRSASigType     rsaSigType          = TRSASigTypePKCS1_5;
        TRSAKeyGenType  rsaKeyGenType       = TRSAKeyGenTypeUnkown;
        TECKeyGenType   ecKeyGenType        = TECKeyGenTypeUnknown;
        NSNumber*       dataUnitSeqNumber   = nil;
        NSNumber*       dataUnitLen         = nil;
        NSData*         classBStaticPrivKey = nil;
        NSData*         classBStaticPubKey  = nil;
        NSData*         classBEphemPrivKey  = nil;
        NSData*         classBEphemPubKey   = nil;
        NSData*         classBSharedSecret  = nil;

        BOOL            groupCountReset     = YES;

        NSNumber*       returnedBitsLen     = nil;

        int             fipsMode            = 0;

        NSData*         ikm                 = nil;
        NSData*         salt                = nil;
        NSData*         info                = nil;
        NSNumber*       okmLength           = nil;


        for (NSString* aLine in lines)              // Process ALL lines in the request file
        {
            // Remove the Windows line endings from all of the lines.
            // This makes our testing house much happier
            lineEndingStr = [[NSMutableString alloc] initWithString:aLine];
            [lineEndingStr replaceOccurrencesOfString:@"\r"
                                           withString:@""
                                              options:0
                                                range:NSMakeRange(0, [lineEndingStr length])];

            aLine = [NSString stringWithString:lineEndingStr];
            [lineEndingStr release];
            lineEndingStr = nil;

            // All request file header lines begin with a "#", but usually contain valuable testing paramter data.
            // We are forced to do ungodly things to determine the real request data, since the files are not normalized.
            // Once the request files are normalized, we will be able to remove this additional parsing of header data.

            // Automatically add any Header line to our array (aLine) for dumping to the corresponding response (.rsp) file.
            if ([aLine hasPrefix:@"#"])
                [fileHeaderStrings addObject:aLine];

            // FIPS POST
            //
            // This isn't actually supplied by the lab, but allows us a method
            // to run POST tests via the same automation endpoints as the CAVS
            // tests.
            if ([aLine hasPrefix:@"# FIPSPOST"])
            {
                testType = TTFIPSPOST;
                sscanf([aLine UTF8String], "# FIPSPOST %d", &fipsMode);
            }

            // HKDF
            if ([aLine isEqualToString:@"# CAVS testing HKDF Test" ])
            {
                testType        = TTHKDF;
            }
            if ([aLine isEqualToString:@"# Hash Name: hmac(sha256)" ])
            {
                cipherType      = TFCipherSHA256;
            }
            if ([aLine hasPrefix:@"IKM = "])
            {
                tempStr = [self getValueFromKeyValuePairString:aLine];
                ikm = HexStringToData(tempStr);
            }
            if ([aLine hasPrefix:@"Salt = "])
            {
                tempStr = [self getValueFromKeyValuePairString:aLine];
                salt = HexStringToData(tempStr);
            }
            if ([aLine hasPrefix:@"Info = "])
            {
                tempStr = [self getValueFromKeyValuePairString:aLine];
                info = HexStringToData(tempStr);
            }
            if ([aLine hasPrefix:@"OKMLength = "])
            {
                tempStr = [self getValueFromKeyValuePairString:aLine];
                NSInteger tempValue = [tempStr integerValue];
                okmLength = [NSNumber numberWithInteger:tempValue];
            }


            // AES-XTS
            //
            // The only way to 'know' if this is an XTS test is to parse the comments.
            if ([aLine hasPrefix:@"#  XTSGen"])
            {
                testType    = TTXTS;
                cipherType  = TFCipherAES;
            }

            // AES-GCM
            //
            // The only way to 'know' if this is a GCM test is to parse the comments.
            // It also is the only way to know if this is for encryption or decryption
            if ([aLine hasPrefix:@"# GCM Decrypt"])
            {
                testType    = TTGCM;
                cipherType  = TFCipherAES;
                encryption  = false;
            }
            if ([aLine hasPrefix:@"# GCM Encrypt"])
            {
                testType    = TTGCM;
                cipherType  = TFCipherAES;
                encryption  = true;
            }

            // AES-CCM
            //
            // The only way to 'know' if this is a CCM test is to parse the comments.
            // It also is the only way to know if this is for encryption or decryption

            if ([aLine hasPrefix:@"#  \"CCM-"]) {
                // Only the CCM tests expect "Count" to count monotonically for the
                // entire file.  Other tests expect the "Count" to be reset to 0 after
                // each test group.
                groupCountReset = NO;

                if ([aLine hasPrefix:@"#  \"CCM-VADT\""])
                {
                    testType    = TTCCMVADT;
                    cipherType  = TFCipherAES;
                    encryption  = true;
                }
                else if ([aLine hasPrefix:@"#  \"CCM-VNT\""])
                {
                    testType    = TTCCMVNT;
                    cipherType  = TFCipherAES;
                    encryption  = true;
                }
                else if ([aLine hasPrefix:@"#  \"CCM-VPT\""])
                {
                    testType    = TTCCMVPT;
                    cipherType  = TFCipherAES;
                    encryption  = true;
                }
                else if ([aLine hasPrefix:@"#  \"CCM-VTT\""])
                {
                    testType    = TTCCMVTT;
                    cipherType  = TFCipherAES;
                    encryption  = true;
                }
                else if ([aLine hasPrefix:@"#  \"CCM-DVPT\""])
                {
                    testType    = TTCCMDVPT;
                    cipherType  = TFCipherAES;
                    encryption  = false;
                }

                if      ([fileName rangeOfString:@"128.req"].length > 0)  length = [NSNumber numberWithInteger:128];
                else if ([fileName rangeOfString:@"192.req"].length > 0)  length = [NSNumber numberWithInteger:192];
                else if ([fileName rangeOfString:@"256.req"].length > 0)  length = [NSNumber numberWithInteger:256];

            }


            // AES-KW & AES-KWP
            //
            if ([aLine rangeOfString:@"NIST SP 800-38F KW"].length > 0)         // Setup testType for AES-KW/AES-KWP
            {
                cipherType = TFCipherAES;

                if ([aLine rangeOfString:@"800-38F KW-AD"].length > 0)
                {
                    testType = TTAESKeyWrap;
                    encryption = false;
                }
                else if ([aLine rangeOfString:@"800-38F KW-AE"].length > 0)
                {
                    testType = TTAESKeyWrap;
                    encryption = true;
                }
                else if ([aLine rangeOfString:@"800-38F KWP-AD"].length > 0)    // Not Yet Implemented in CoreCrypto
                {
                    testType = TTAESKeyWrapPad;
                    encryption = false;
                }
                else if ([aLine rangeOfString:@"800-38F KWP-AE"].length > 0)    // Not Yet Implemented in CoreCrypto
                {
                    testType = TTAESKeyWrapPad;
                    encryption = true;
                }
                else
                    fprintf(stderr, "This is a Non-Supported Key Wrapping Function\n");

            }
            if ([aLine isMatchedByRegex:@"# Seed ="])                           // found in AES-KW, AES-KWP
            {
                tempStr     = [self getValueFromKeyValuePairString:aLine];
                msg         = HexStringToData(tempStr);
            }

            // ECDH - Function Tests
            //
            if ([aLine hasPrefix:@"#  ECC Function Test"])                      // Setup testType for ECDH Function Tests
            {
                cipherType = TFCipherECC;

                if ([aLine rangeOfString:@"dhEphemeralUnified"].length > 0)     // Not Implemented in CoreCrypto
                {
                    testType = TTECDHPrimFuncEphemeralUnified;
                }
                else if ([aLine rangeOfString:@"dhFullUnified"].length > 0)     // Not Implemented in CoreCrypto
                {
                    testType = TTECDHPrimFuncFullUnified;
                }
                else if ([aLine rangeOfString:@"dhOnePassDH"].length > 0)       // Only one we support in CoreCrypto
                {
                    if ([fileName rangeOfString:@"NOKC_ZZOnly"].length > 0)     // Only one we support in CoreCrypto
                    {
                        testType = TTECDHPrimFuncOnePassDH;
                    }
                    else if ([fileName rangeOfString:@"KDFConcat"].length > 0)  // Not Implemented in CoreCrypto
                    {
                        testType = TTECDHPrimFuncOnePassDH_KDFConcat;
                    }

                }
                else if ([aLine rangeOfString:@"dhOnePassUnified"].length > 0)  // Not Implemented in CoreCrypto
                {
                    testType = TTECDHPrimFuncOnePassUnified;
                }
                else if ([aLine rangeOfString:@"dhStaticUnified"].length > 0)   // Not Implemented in CoreCrypto
                {
                    testType = TTECDHPrimFuncStaticUnified;
                }
                else
                {
                     fprintf(stderr, "This is a Non-Supported ECC Function Test.\n");    // Unknown & Unsupported
                }
            }

            // ECDH - Validity Tests
            //
            if ([aLine hasPrefix:@"#  ECC Validity Test"])                      // Setup testType for ECDH Validity Tests
            {
                cipherType = TFCipherECC;

                if ([aLine rangeOfString:@"dhEphemeralUnified"].length > 0)     // Not Implemented in CoreCrypto
                {
                    testType = TTECDHPrimValEphemeralUnified;

                }
                else if ([aLine rangeOfString:@"dhFullUnified"].length > 0)     // Not Implemented in CoreCrypto
                {
                    testType = TTECDHPrimValFullUnified;

                }
                else if ([aLine rangeOfString:@"dhOnePassDH"].length > 0)       // Only one we support in CoreCrypto
                {
                    if ([fileName rangeOfString:@"NOKC_ZZOnly"].length > 0)     // Only one we support in CoreCrypto
                    {
                        testType = TTECDHPrimValOnePassDH;
                    }
                    else if ([fileName rangeOfString:@"KDFConcat"].length > 0)  // Not Implemented in CoreCrypto
                    {
                        testType = TTECDHPrimValOnePassDH_KDFConcat;
                    }

                }
                else if ([aLine rangeOfString:@"dhOnePassUnified"].length > 0)  // Not Implemented in CoreCrypto
                {
                    testType = TTECDHPrimValOnePassUnified;

                }
                else if ([aLine rangeOfString:@"dhStaticUnified"].length > 0)   // Not Implemented in CoreCrypto
                {
                    testType = TTECDHPrimValStaticUnified;

                }
                else
                {
                    fprintf(stderr, "This is a Non-Supported ECC Validity Test.\n");    // Unknown & Unsupported
                }
            }


            // AES - Multiple iOS Implementations
            //
            // There are three seperate implementations of AES for iOS.
            // 'normal'         - V&N groups implementation
            // 'non-optimized'  - LTC implementation
            // 'hardware'       - Silicon
            // The way to determine this is to read the names in the config info
            // header to the test.  This tests below look for those names and
            // will set 'aesImplType' to the corresponding value.
            if ([aLine rangeOfString:@"APPLE AES SOFTWARE IMPLEMENTATION"].length > 0)
                aesImplType = TAESIMPLNormal;
            else if ([aLine rangeOfString:@"AES NON-OPTIMIZED SOFTWARE IMPLEMENTATION"].length > 0)
                aesImplType = TAESIMPLNonOptimized;
            else if ([aLine rangeOfString:@"APPLE AES HARDWARE"].length > 0)
                aesImplType = TAESIMPLHardware;


            // ECDSA2 - FIPS 186-4
            //
            if ([aLine hasPrefix:@"#  \"PKV\"" ])               // ECC: Public Key Verification
            {
                cipherType  = TFCipherECC;
                testType    = TTECPublicKeyVerification;
            }
            if ([aLine hasPrefix:@"#  \"Key Pair\"" ])          // ECC: Key Pair Generation
            {
                cipherType  = TFCipherECC;
                testType    = TTECKeyGeneration;
            }
            if ([aLine hasPrefix:@"#  \"SigGen\"" ])            // ECC: Signature Generation
            {
                cipherType  = TFCipherECC;
                testType    = TTECSignatureGeneration;
            }
            if ([aLine hasPrefix:@"#  \"SigGenComponent\"" ])   // ECC: Signature Generation Component
            {
                cipherType  = TFCipherECC;
                testType    = TTECSignatureGenerationComponent;
            }

            // RSA2 - FIPS 186-4
            //
            if ([aLine hasPrefix:@"# \"FIPS186-4 - KeyGen" ])   // RSA: Key Pair Generation
            {
                cipherType  = TFCipherRSA;
                testType    = TTRSAKeyGeneration;

                // Determine which variant for primes testing and set rsaKeyGenType
                if ([aLine isMatchedByRegex:@"Random Probably Prime Test"])
                    rsaKeyGenType = TRSAKeyGenTypeRandProbPrime;
                else if ([aLine isMatchedByRegex:@"Random Probably Prime Known Answer Test"])
                    rsaKeyGenType = TRSAKeyGenTypeRandProbPrimeKAT;
                else
                    rsaKeyGenType = TRSAKeyGenTypeProbPrimeWithCondition;
            }

            // Curve25519-ECDH
            //
            if ([aLine isEqualToString:@"# CAVS testing Curve25519 ECDH Function Test" ])
            {
                testType        = TTECDHCurve25519GenerateShared;
                cipherType      = TFCipherCurve25519;
                ecDigestType    = TFCipherSHA256;
            }
            else if  ([aLine isEqualToString:@"# CAVS testing Curve25519 ECDH Validity" ])
            {
                testType        = TTECDHCurve25519VerifyShared;
                cipherType      = TFCipherCurve25519;
                ecDigestType    = TFCipherSHA256;
            }
            else if ([aLine isEqualToString:@"# CAVS testing Curve25519 Key Verification" ])
            {
                testType        = TTECDHCurve25519KeyVerify;
                cipherType      = TFCipherCurve25519;
                ecDigestType    = TFCipherSHA256;
            }
            else if ([aLine isEqualToString:@"# CAVS testing Ed25519 Key Verification" ])
            {
                testType        = TTECDHCurve25519KeyVerify;
                cipherType      = TFCiphered25519;
                ecDigestType    = TFCipherSHA256;
            }
            else if ([aLine isEqualToString:@"# CAVS testing Curve25519 Key Generation" ])
            {
                testType        = TTECDHCurve25519KeyGenerate;
                cipherType      = TFCipherCurve25519;
                ecDigestType    = TFCipherSHA256;
            //  numbKeys        =  We will capture this as an environment variable [N = (.*)]
            }
            else if ([aLine isEqualToString:@"# CAVS testing Ed25519 Key Generation" ])
            {
                testType        = TTECDHCurve25519KeyGenerate;
                cipherType      = TFCiphered25519;
                ecDigestType    = TFCipherSHA256;
            //  numbKeys        =  We will capture this as an environment variable [N = (.*)]
            }


            if ([aLine hasPrefix:@"#  \"KeyPair\" information for"])
            {
                testType        = TTFFDHKeyGenerate;
            }

            if ([aLine hasPrefix:@"#  FFC Function Test for dhEphem"])
            {
                testType        = TTFFDHFunction;
            }

            if ([aLine hasPrefix:@"#  FFC Validity Test for dhEphem Key Agreement"])
            {
                testType        = TTFFDHValidity;
            }

            // Want to skip lines that are Informational ONLY and need not be processed any further.
            // This will improve processing time, but is FRAGILE if CMVP changes the file format.
            // One day, CMVP will provide normalized files (i.e. XML) and this can all go away.

            if ([aLine isEqual:@""]                          ||
                [aLine hasPrefix:@"# CAVS "]                 ||  // CAVS Tool Version - ie. # CAVS 17.0
                [aLine hasPrefix:@"#  CAVS "]                ||  // CAVS Tool Version - ie. # CAVS 20.0
                [aLine hasPrefix:@"# NOTE: "]                ||  // NOTE to implementor on the FIPS standard
                [aLine hasPrefix:@"# Combinations"]          ||  // Combinations Mod/SHA-<size> appearing in the test data
                [aLine hasPrefix:@"# Generated"]             ||  // Date the CAVS Request Vectors were generated
                [aLine hasPrefix:@"#  Generated"]            ||  // Date the CAVS Request .... for CAVS 20.0 and later
                [aLine hasPrefix:@"# #Mod(s):"]              ||  // Mod Size (2048,3072,...)
                [aLine hasPrefix:@"# Mod(s):"]               ||  // Mod Size (2048,3072,...)
                [aLine hasPrefix:@"# Calculating"]           ||
                [aLine hasPrefix:@"# #Calculating"]          ||
                [aLine hasPrefix:@"# Public Keys"]           ||
                [aLine hasPrefix:@"# Prime types selected"]  ||
                [aLine hasPrefix:@"# Primes with Conditions"]||
                [aLine hasPrefix:@"#  Curves/SHAs"]          ||
                [aLine hasPrefix:@"#  Parameter set(s)"]     ||
                [aLine hasPrefix:@"#  CAVSid:"])
            {

            } // Just skip any further processing of this paticular line...

            else    // Need to do lots more voodoo to process this line
            {

                // Determining the list of environment variables is a bit of voodoo given
                // how the NIST CAVS files are written.  They will be normalized in the future,
                // but until then the following is the evil we must deal with.

                if ([aLine hasPrefix:@"["])                 // An environment variable has been found.
                {
                    // If testFound is YES then this is set of environment variables after the
                    // the first set of environment variables.  First clean up the
                    // previous set of environment data along with all of the test seen.

                    if (testFound)
                    {
                        // Set the current set of test Environment variables into the Test Group Dictionary
                        [tempTestGroupDictionary setObject:tempTestEnvironItems forKey:TFEnvironmentDataKey];
                        // Now that the data has been saved make a new array to hold new environment variables.
                        tempTestEnvironItems    = [NSMutableArray array];

                        // Set the current set of tests seen before getting this environment variable.
                        [tempTestGroupDictionary setObject:tempTestItems forKey:TFTestKey];
                        // Now that the data has been saved make a new array to hold the new tests
                        tempTestItems           = [NSMutableArray array];

                        // Add the existing Test Group Dictionary to the array of test groups
                        [tempTestGroupArray addObject:tempTestGroupDictionary];
                        // Now that the data has been saved make a new Test Group Dictionary
                        tempTestGroupDictionary = [NSMutableDictionary dictionary];
                    }

                    // Not sure why we need to do all of these, but it seems we have parsing errors otherwise
                    // TODO:  need to clean this all up
                    //
                    if (([aLine isMatchedByRegex:@"[mod = (.*)]"])                           &&
                        !([aLine hasPrefix:@"[Table for M"])                                 &&
                        !([aLine hasPrefix:@"[hash"])                                        &&
                        !([aLine isEqualToString:@"[PrimeMethod = ProbPC]"])                 &&
                        !([aLine isEqualToString:@"[PrimeMethod = Probable Random Primes]"]) &&
                        !([aLine hasPrefix:@"[B"]) )
                    {
                        tempStr = [[[self getValueFromKeyValuePairString:aLine]
                        stringByReplacingOccurrencesOfString:@"]" withString:@""] uppercaseString];
                        NSInteger tempKeySize = [tempStr integerValue];

                        rsaKeySize = [NSNumber numberWithInteger:tempKeySize];
                    }

                    // Acquire the correct cipherType for the HMAC_DRBG vectors
                    if ([aLine isEqualToString:@"[SHA-1]"]) { cipherType = TFCipherSHA1; }
                    else if ([aLine isEqualToString:@"[SHA-1]"])     cipherType  = TFCipherSHA1;
                    else if ([aLine isEqualToString:@"[SHA-224]"])   cipherType  = TFCipherSHA224;
                    else if ([aLine isEqualToString:@"[SHA-256]"])   cipherType  = TFCipherSHA256;
                    else if ([aLine isEqualToString:@"[SHA-384]"])   cipherType  = TFCipherSHA384;
                    else if ([aLine isEqualToString:@"[SHA-512]"])   cipherType  = TFCipherSHA512;
                    else if ([aLine isEqualToString:@"[SHA3-224]"])  cipherType  = TFCipherSHA3_224;
                    else if ([aLine isEqualToString:@"[SHA3-256]"])  cipherType  = TFCipherSHA3_256;
                    else if ([aLine isEqualToString:@"[SHA3-384]"])  cipherType  = TFCipherSHA3_384;
                    else if ([aLine isEqualToString:@"[SHA3-512]"])  cipherType  = TFCipherSHA3_512;

                    // For GCM tests the IVLength and TagLength needs to be kept
                    //
                    if ([aLine hasPrefix:@"[IVlen"])
                    {
                        NSCharacterSet* squareBracketSet = [NSCharacterSet characterSetWithCharactersInString:@"[]"];
                        tempStr = [aLine stringByTrimmingCharactersInSet:squareBracketSet];
                        NSCharacterSet* spaceBracketSet = [NSCharacterSet characterSetWithCharactersInString:@" "];
                        tempStr = [tempStr stringByTrimmingCharactersInSet:spaceBracketSet];
                        NSArray*    tempArray   = [tempStr componentsSeparatedByString:@"="];
                        NSString*   lengthStr   = [tempArray objectAtIndex:1];
                        NSInteger   tempIVSize  = [lengthStr integerValue];
                        tempIVSize /= 8;        // change from bits to bytes
                        ivLen = [NSNumber numberWithInteger:tempIVSize];
                    }

                    if ([aLine hasPrefix:@"[Taglen"])
                    {
                        NSCharacterSet* squareBracketSet = [NSCharacterSet characterSetWithCharactersInString:@"[]"];
                        tempStr = [aLine stringByTrimmingCharactersInSet:squareBracketSet];
                        NSCharacterSet* spaceBracketSet = [NSCharacterSet characterSetWithCharactersInString:@" "];
                        tempStr = [tempStr stringByTrimmingCharactersInSet:spaceBracketSet];
                        NSArray*    tempArray   = [tempStr componentsSeparatedByString:@"="];
                        NSString*   lengthStr   = [tempArray objectAtIndex:1];
                        NSInteger   tempTagSize = [lengthStr integerValue];
                        tempTagSize /= 8;       // change from bits to bytes
                        tagLength = [NSNumber numberWithInteger:tempTagSize];
                    }

                    if ([aLine hasPrefix:@"[PTlen"])
                    {
                        NSCharacterSet* squareBracketSet = [NSCharacterSet characterSetWithCharactersInString:@"[]"];
                        tempStr = [aLine stringByTrimmingCharactersInSet:squareBracketSet];
                        NSCharacterSet* spaceBracketSet = [NSCharacterSet characterSetWithCharactersInString:@" "];
                        tempStr = [tempStr stringByTrimmingCharactersInSet:spaceBracketSet];
                        NSArray*    tempArray    = [tempStr componentsSeparatedByString:@"="];
                        NSString*   lengthStr    = [tempArray objectAtIndex:1];
                        NSInteger   tempPTLength = [lengthStr integerValue];
                        tempPTLength /= 8;      // change from bits to bytes
                        ptLength = [NSNumber numberWithInteger:tempPTLength];
                    }

                    if ([aLine hasPrefix:@"[AADlen"])
                    {
                        NSCharacterSet* squareBracketSet = [NSCharacterSet characterSetWithCharactersInString:@"[]"];
                        tempStr = [aLine stringByTrimmingCharactersInSet:squareBracketSet];
                        NSCharacterSet* spaceBracketSet = [NSCharacterSet characterSetWithCharactersInString:@" "];
                        tempStr = [tempStr stringByTrimmingCharactersInSet:spaceBracketSet];
                        NSArray*    tempArray       = [tempStr componentsSeparatedByString:@"="];
                        NSString*   lengthStr       = [tempArray objectAtIndex:1];
                        NSInteger   tempAADLength   = [lengthStr integerValue];
                        tempAADLength /= 8;     // change from bits to bytes
                        aadLength = [NSNumber numberWithInteger:tempAADLength];
                    }

                    if ([aLine hasPrefix:@"[P-"])
                    {
                        NSCharacterSet* squareBracketSet = [NSCharacterSet characterSetWithCharactersInString:@"[]"];
                        tempStr = [aLine stringByTrimmingCharactersInSet:squareBracketSet];
                        NSCharacterSet* spaceBracketSet = [NSCharacterSet characterSetWithCharactersInString:@" "];
                        tempStr = [tempStr stringByTrimmingCharactersInSet:spaceBracketSet];
                        NSArray*    tempArray   = [tempStr componentsSeparatedByString:@"-"];
                        NSString*   lengthStr   = [tempArray objectAtIndex:1];
                        NSInteger   tempCurve   = [lengthStr integerValue];
                        curve = [NSNumber numberWithInteger:tempCurve];

                        if      ([aLine isMatchedByRegex:@"SHA-1"])     ecDigestType = TFCipherSHA1;
                        else if ([aLine isMatchedByRegex:@"SHA-224"])   ecDigestType = TFCipherSHA224;
                        else if ([aLine isMatchedByRegex:@"SHA-256"])   ecDigestType = TFCipherSHA256;
                        else if ([aLine isMatchedByRegex:@"SHA-384"])   ecDigestType = TFCipherSHA384;
                        else if ([aLine isMatchedByRegex:@"SHA-512"])   ecDigestType = TFCipherSHA512;
                        else if ([aLine isMatchedByRegex:@"SHA3-224"])  ecDigestType = TFCipherSHA3_224;
                        else if ([aLine isMatchedByRegex:@"SHA3-256"])  ecDigestType = TFCipherSHA3_256;
                        else if ([aLine isMatchedByRegex:@"SHA3-384"])  ecDigestType = TFCipherSHA3_384;
                        else if ([aLine isMatchedByRegex:@"SHA3-512"])  ecDigestType = TFCipherSHA3_512;
                    }


                    if ([aLine isEqual:@"[EB - SHA256]"])
                    {
                        ecDigestType =  TFCipherSHA256;
                        curve =         [NSNumber numberWithInteger:224];
                        klen =          [NSNumber numberWithInteger:112];
                        tagLength =     [NSNumber numberWithInteger:64];
                    }
                    else if ([aLine isEqual:@"[EC - SHA256]"])
                    {
                        ecDigestType =  TFCipherSHA256;
                        curve =         [NSNumber numberWithInteger:256];
                        klen =          [NSNumber numberWithInteger:128];
                        tagLength =     [NSNumber numberWithInteger:64];

                    }
                    else if ([aLine isEqual:@"[ED - SHA384]"])
                    {
                        ecDigestType =  TFCipherSHA384;
                        curve =         [NSNumber numberWithInteger:384];
                        klen =          [NSNumber numberWithInteger:192];
                        tagLength =     [NSNumber numberWithInteger:192];
                    }
                    else if ([aLine isEqual:@"[EE - SHA512]"])
                    {
                        ecDigestType =  TFCipherSHA256;
                        curve =         [NSNumber numberWithInteger:521];
                        klen =          [NSNumber numberWithInteger:256];
                        tagLength =     [NSNumber numberWithInteger:256];
                    }


                    if ([aLine hasPrefix:@"[DECRYPT"])      encryption = false;


                    // RSA - FIPS 186-4
                    //
                    if ([aLine hasPrefix:@"[PrimeMethod"])
                    {
                        if ([aLine isMatchedByRegex:@"ProbPC"])
                            rsaKeyGenType = TRSAKeyGenTypeProbPrimeWithCondition;
                        else if ([aLine isMatchedByRegex:@"Probable Random Primes"])
                            rsaKeyGenType = TRSAKeyGenTypeRandProbPrimeKAT;

                        testFound = false;
                    }


                    // ECDSA - FIPS 186-4
                    //
                    if ([aLine hasPrefix:@"[B.4"])
                    {
                        if ([aLine hasPrefix:@"[B.4.1"])
                            ecKeyGenType = TECKeyGenTypeRandomBits;
                        else if ([aLine hasPrefix:@"[B.4.2"])
                            ecKeyGenType = TECKeyGenTypeTestingCandidates;
                        else
                            ecKeyGenType = TECKeyGenTypeUnknown;
                    }


                    // AES-KW, AES-KWP
                    //
                    if ([aLine hasPrefix:@"[PLAINTEXT LENGTH"])                      // found in AES-KW, AES-KWP
                    {
                        if (nil != plainText)
                        {
                            fprintf(stderr, "PLAINTEXT seen twice - input file junk.\n");
                            [pool drain];
                            return result;
                        }

                        NSCharacterSet* squareBracketSet = [NSCharacterSet characterSetWithCharactersInString:@"[]"];
                        tempStr = [aLine stringByTrimmingCharactersInSet:squareBracketSet];
                        NSCharacterSet* spaceBracketSet = [NSCharacterSet characterSetWithCharactersInString:@" "];
                        tempStr = [tempStr stringByTrimmingCharactersInSet:spaceBracketSet];
                        NSArray*    tempArray       = [tempStr componentsSeparatedByString:@"="];
                        NSString*   lengthStr       = [tempArray objectAtIndex:1];
                        NSInteger   tempPTLength    = [lengthStr integerValue];
                        ptLength = [NSNumber numberWithInteger:tempPTLength];
                    }
                    else if ([aLine isMatchedByRegex:@"^CIPHERTEXT LENGTH = (.*)"])  // found in AES-KW, AES-KWP
                    {
                        if (nil != plainText)
                        {
                            fprintf(stderr, "CIPHERTEXT seen twice - input file junk\n");
                            [pool drain];
                            return result;
                        }

                        NSCharacterSet* squareBracketSet = [NSCharacterSet characterSetWithCharactersInString:@"[]"];
                        tempStr = [aLine stringByTrimmingCharactersInSet:squareBracketSet];
                        NSCharacterSet* spaceBracketSet = [NSCharacterSet characterSetWithCharactersInString:@" "];
                        tempStr = [tempStr stringByTrimmingCharactersInSet:spaceBracketSet];
                        NSArray*    tempArray       = [tempStr componentsSeparatedByString:@"="];
                        NSString*   lengthStr       = [tempArray objectAtIndex:1];
                        NSInteger   tempPTLength    = [lengthStr integerValue];
                        ptLength = [NSNumber numberWithInteger:tempPTLength];
                    }

                    // AES-CCM
                    if ([aLine hasPrefix:@"[Alen = "])              // Tests: AES-CCM
                    {
                        if ([fileName rangeOfString:@"DVPT"].length > 0) {
                            // This means we have an unusual case of all parameters packed on one line
                            //  ie. [Alen = 0, Plen = 0, Nlen = 7, Tlen = 4]
                            //  Due to lack of time, we will take a horrible approach :-(
                            //  here for now and improve processing later.
                            //  Possible combinations...
                            //      [Alen = 0|32, Plen = 0|32, Nlen = 7|13, Tlen = 4|16]

                            if ([aLine rangeOfString:@"Alen = 0"].length > 0)
                                alen    = [NSNumber numberWithInteger:0];
                            else
                                alen    = [NSNumber numberWithInteger:32];

                            if ([aLine rangeOfString:@"Plen = 0"].length > 0)
                                plen    = [NSNumber numberWithInteger:0];
                            else
                                plen    = [NSNumber numberWithInteger:32];

                            if ([aLine rangeOfString:@"Nlen = 7"].length > 0)
                                nlen    = [NSNumber numberWithInteger:7];
                            else
                                nlen    = [NSNumber numberWithInteger:13];

                            if ([aLine rangeOfString:@"Tlen = 4"].length > 0)
                                tlen    = [NSNumber numberWithInteger:4];
                            else
                                tlen    = [NSNumber numberWithInteger:16];
                        }
                        else {
                            NSCharacterSet* squareBracketSet = [NSCharacterSet characterSetWithCharactersInString:@"[]"];
                            tempStr = [aLine stringByTrimmingCharactersInSet:squareBracketSet];
                            NSCharacterSet* spaceBracketSet = [NSCharacterSet characterSetWithCharactersInString:@" "];
                            tempStr = [tempStr stringByTrimmingCharactersInSet:spaceBracketSet];
                            NSArray*    tempArray   = [tempStr componentsSeparatedByString:@"="];
                            NSString*   lengthStr   = [tempArray objectAtIndex:1];
                            NSInteger   tempTagSize = [lengthStr integerValue];
                            alen        = [NSNumber numberWithInteger:tempTagSize];
                        }

                        // Clear these two out for next set of tests
                        key = nil;
                        nonce = nil;
                    }

                    // AES-CCM
                    if ([aLine hasPrefix:@"[Tlen = "])              // Tests: AES-CCM
                    {
                        NSCharacterSet* squareBracketSet = [NSCharacterSet characterSetWithCharactersInString:@"[]"];
                        tempStr = [aLine stringByTrimmingCharactersInSet:squareBracketSet];
                        NSCharacterSet* spaceBracketSet = [NSCharacterSet characterSetWithCharactersInString:@" "];
                        tempStr = [tempStr stringByTrimmingCharactersInSet:spaceBracketSet];
                        NSArray*    tempArray   = [tempStr componentsSeparatedByString:@"="];
                        NSString*   lengthStr   = [tempArray objectAtIndex:1];
                        NSInteger   tempValue   = [lengthStr integerValue];
                        tlen        = [NSNumber numberWithInteger:tempValue];

                        // Clear these two out for next set of tests
                        key = nil;
                        nonce = nil;
                    }

                    // AES-CCM
                    if ([aLine hasPrefix:@"[Nlen = "])              // Tests: AES-CCM
                    {
                        NSCharacterSet* squareBracketSet = [NSCharacterSet characterSetWithCharactersInString:@"[]"];
                        tempStr = [aLine stringByTrimmingCharactersInSet:squareBracketSet];
                        NSCharacterSet* spaceBracketSet = [NSCharacterSet characterSetWithCharactersInString:@" "];
                        tempStr = [tempStr stringByTrimmingCharactersInSet:spaceBracketSet];
                        NSArray*    tempArray   = [tempStr componentsSeparatedByString:@"="];
                        NSString*   lengthStr   = [tempArray objectAtIndex:1];
                        NSInteger   tempValue   = [lengthStr integerValue];
                        nlen        = [NSNumber numberWithInteger:tempValue];

                        // Clear out for next set of tests
                        key = nil;
                    }

                    // AES-CCM
                    if ([aLine hasPrefix:@"[Plen = "])              // Tests: AES-CCM
                    {
                        NSCharacterSet* squareBracketSet = [NSCharacterSet characterSetWithCharactersInString:@"[]"];
                        tempStr = [aLine stringByTrimmingCharactersInSet:squareBracketSet];
                        NSCharacterSet* spaceBracketSet = [NSCharacterSet characterSetWithCharactersInString:@" "];
                        tempStr = [tempStr stringByTrimmingCharactersInSet:spaceBracketSet];
                        NSArray*    tempArray   = [tempStr componentsSeparatedByString:@"="];
                        NSString*   lengthStr   = [tempArray objectAtIndex:1];
                        NSInteger   tempValue   = [lengthStr integerValue];
                        plen            = [NSNumber numberWithInteger:tempValue];

                        // Clear out for next set of tests
                        key = nil;
                        nonce = nil;
                    }

                    //
                    // Add the environment data to the cumulative "temptTestEnvironItems" array
                    //
                    [tempTestEnvironItems addObject:aLine];
                }

                if ([aLine hasPrefix:@"[ReturnedBitsLen = "]) {            // Tests: HMAC-DRBG
                    NSCharacterSet* squareBracketSet = [NSCharacterSet characterSetWithCharactersInString:@"[]"];
                    tempStr = [aLine stringByTrimmingCharactersInSet:squareBracketSet];
                    NSCharacterSet* spaceBracketSet = [NSCharacterSet characterSetWithCharactersInString:@" "];
                    tempStr = [tempStr stringByTrimmingCharactersInSet:spaceBracketSet];
                    NSArray*    tempArray   = [tempStr componentsSeparatedByString:@"="];
                    NSString*   lengthStr   = [tempArray objectAtIndex:1];
                    NSInteger   tempValue   = [lengthStr integerValue];
                    returnedBitsLen         = [NSNumber numberWithInteger:tempValue];
                }


                //  More Voodoo...
                //
                if (!testFound && [aLine isMatchedByRegex:@"^(COUNT|Count|SHAAlg|n|Len|Seed|NumKeys|e|N|Qx|Msg) ="])
                {
                    // RSA2 RandProbPrimeKAT tripping up parser here on first "e = ..", so avoid
                    // Also, now handling of AES-CCM files casues failure here if we do not skip them at this point

                    if ((rsaKeyGenType != TRSAKeyGenTypeRandProbPrimeKAT)) {
                        testFound = true;
                    }

                    if ([aLine isMatchedByRegex:@"NumKeys = (.*)"])
                    {
                        tempStr = [self getValueFromKeyValuePairString:aLine];
                        NSInteger
                        numKeysNum   = [tempStr integerValue];
                        numKeysValue = [NSNumber numberWithInteger:numKeysNum];
                    }

                    if (([aLine isMatchedByRegex:@"n = (.*)"] && (rsaKeyGenType == TRSAKeyGenTypeProbPrimeWithCondition)) ||
                        ([aLine isMatchedByRegex:@"N = (.*)"] && (rsaKeyGenType == TRSAKeyGenTypeRandProbPrime)))
                    {
                        tempStr = [self getValueFromKeyValuePairString:aLine];
                        NSInteger
                        numKeysNum   = [tempStr integerValue];
                        numKeysValue = [NSNumber numberWithInteger:numKeysNum];
                    }

                    if ([aLine isMatchedByRegex:@"N = (.*)"] && (ecKeyGenType != TECKeyGenTypeUnknown))
                    {
                        capitalNData = nil;
                    }
                }

                if ([aLine isMatchedByRegex:@"N = (.*)"] &&                     // Are we processing "N = (.*)" a 2nd time ?
                    ((rsaKeyGenType == TRSAKeyGenTypeRandProbPrime)      ||
                     (ecKeyGenType  == TECKeyGenTypeRandomBits)          ||
                     (ecKeyGenType  == TECKeyGenTypeTestingCandidates)   ||
                     (testType      == TTECDHCurve25519KeyGenerate)      ||
                     (testType      == TTFFDHKeyGenerate)                ))
                {
                    tempStr = [self getValueFromKeyValuePairString:aLine];
                    NSInteger
                    numKeysNum   = [tempStr integerValue];
                    numKeysValue = [NSNumber numberWithInteger:numKeysNum];
                }


                if ([aLine isMatchedByRegex:@"PredictionResistance = (.*)"])
                {
                    tempStr = [[[self getValueFromKeyValuePairString:aLine]
                                stringByReplacingOccurrencesOfString:@"]"
                                                          withString:@""]
                                                           uppercaseString];

                    // Set predictionResistance Flag appropriately
                    if      ([tempStr isEqualToString:@"TRUE"])     predictionResistance = YES;
                    else if ([tempStr isEqualToString:@"FALSE"])    predictionResistance = NO;
                    else    fprintf(stderr, "Unable to parse the predictionResistance input line: %s\n", [aLine UTF8String]);
                }

                if ([aLine isMatchedByRegex:@"^#.*(CBC|ECB|OFB|CFB|SHA-|SigGen|SigVer|RC4VS|ANSI X9.31|Hash sizes tested|PQGGen|KeyGen RSA|HMAC|CTR_DRBG|Curves selected)"])
                {
                    if      ([aLine isMatchedByRegex:@"CBC"])       modeType    = TFModeCBC;
                    else if ([aLine isMatchedByRegex:@"ECB"])       modeType    = TFModeECB;
                    else if ([aLine isMatchedByRegex:@"OFB"])       modeType    = TFModeOFB;
                    else if ([aLine isMatchedByRegex:@"CFB8"])      modeType    = TFModeCFB8;
                    else if ([aLine isMatchedByRegex:@"CFB"])       modeType    = TFModeCFB;
                    else if ([aLine isMatchedByRegex:@"SHA-1"])     cipherType  = TFCipherSHA1;
                    else if ([aLine isMatchedByRegex:@"SHA-224"])   cipherType  = TFCipherSHA224;
                    else if ([aLine isMatchedByRegex:@"SHA-256"])   cipherType  = TFCipherSHA256;
                    else if ([aLine isMatchedByRegex:@"SHA-384"])   cipherType  = TFCipherSHA384;
                    else if ([aLine isMatchedByRegex:@"SHA-512"])   cipherType  = TFCipherSHA512;
                    else if ([aLine isMatchedByRegex:@"SHA3-224"])  cipherType  = TFCipherSHA3_224;
                    else if ([aLine isMatchedByRegex:@"SHA3-256"])  cipherType  = TFCipherSHA3_256;
                    else if ([aLine isMatchedByRegex:@"SHA3-384"])  cipherType  = TFCipherSHA3_384;
                    else if ([aLine isMatchedByRegex:@"SHA3-512"])  cipherType  = TFCipherSHA3_512;
                    else if ([aLine isMatchedByRegex:@"RC4VS"])     cipherType  = TFCipherRC4;
                    else if ([aLine isMatchedByRegex:@"HMAC"])      cipherType  = TFCipherHMAC;
                    else if ([aLine isMatchedByRegex:@"CTR_DRBG"])  cipherType  = TFCipherDRBG;
                    else if ([aLine isMatchedByRegex:@"(SigGen|SigVer)"])
                    {
                        if ([aLine isMatchedByRegex:@"SigGen"])
                        {
                            rsaSigType = TRSASigTypePKCS1_5;

                            if      ([aLine isMatchedByRegex:@"RSA"] && ([aLine isMatchedByRegex:@"X9.31"]))
                            {
                                // This means that there is a line in the test file LIKE
                                // # "SigVer RSA (X9.31)" information
                                if (dispatcher.verbose) printf("RSA SigGen using X9.31\n");

                                cipherType  = TFCipherRSA;
                                rsaSigType  = TRSASigTypeX9_31;
                                testType    = TTRSASignatureGeneration;
                            }
                            else if ([aLine isMatchedByRegex:@"PKCS#1"])
                            {
                                // This means that theer is a line in the test file LIKE
                                // # "SigVer PKCS#1 Ver 1.5" information
                                if (dispatcher.verbose) printf("RSA SigGen using PKCS 1.5\n");

                                cipherType  = TFCipherRSA;
                                rsaSigType  = TRSASigTypePKCS1_5;
                                testType    = TTRSASignatureGeneration;
                            }

                        }
                        else    // is for SigVer then
                        {
                            rsaSigType      = TRSASigTypePKCS1_5;
                            if      ([aLine isMatchedByRegex:@"RSA"] && ([aLine isMatchedByRegex:@"X9.31"]))
                            {
                                if (dispatcher.verbose) printf("RSA SigVers using X9.31\n");

                                // This means that there is a line in the test file LIKE
                                // # "SigVer RSA (X9.31)" information
                                cipherType  = TFCipherRSA;
                                rsaSigType  = TRSASigTypeX9_31;
                                testType    = TTRSASignatureVerification;
                            }
                            else if ([aLine isMatchedByRegex:@"PKCS#1"])
                            {
                                if (dispatcher.verbose) printf("RSA SigVers using PKCS 1.5\n");

                                // This means that there is a line in the test file LIKE
                                // # "SigVer PKCS#1 Ver 1.5" information
                                cipherType  = TFCipherRSA;
                                rsaSigType  = TRSASigTypePKCS1_5;
                                testType    = TTRSASignatureVerification;
                            }
                            else        // Else we are processing SigVer for ECDSA
                            {
                                if (dispatcher.verbose) printf("Setting up a SigVer for ECDSA\n");

                                cipherType  = TFCipherECC;
                                testType    = TTECSignatureVerification;
                            }
                        }
                    }

                    if      ([aLine isMatchedByRegex:@"^# AESVS"])   cipherType = TFCipherAES;

                    if      (([aLine isMatchedByRegex:@"^# TDES"]) ||
                             ([aLine isMatchedByRegex:@"^#.*KAT"]))  cipherType = TFCipher3DES;

                    if ([aLine isMatchedByRegex:@"Curves selected:"]) cipherType = TFCipherECC;



                    // Identify the test type
                    if (TTUnknownTestType == testType)
                    {
                        if      ([aLine rangeOfString:@"KeyGen RSA (X9.31)"].length > 0) testType = TTRSAKeyGeneration;
                        else if ([aLine rangeOfString:@"FIPS186-4 - KeyGen"].length > 0) testType = TTRSAKeyGeneration;
                        else if ([aLine rangeOfString:@"PQGGen"].length > 0)             testType = TTDSAPQGGen;
                        else if ([aLine rangeOfString:@"Hash sizes tested"].length > 0)  testType = TTHMAC;
                        else if ([aLine rangeOfString:@"HMAC_DRBG"].length > 0)          testType = TTHMACDRBG;
                        else if(([aLine rangeOfString:@"ANSI X9.31"].length > 0) &&
                                ([aLine rangeOfString:@"MCT"].length > 0))               testType = TTRNGMCT;
                        else if(([aLine rangeOfString:@"ANSI X9.31"].length > 0) &&
                                ([aLine rangeOfString:@"VST"].length > 0))               testType = TTRNGKAT;

                        else if ([aLine isMatchedByRegex:@"(Monte|MCT|Carlo)"] &&
                                 ((cipherType == TFCipherSHA1)      ||
                                  (cipherType == TFCipherSHA224)    ||
                                  (cipherType == TFCipherSHA256)    ||
                                  (cipherType == TFCipherSHA384)    ||
                                  (cipherType == TFCipherSHA512)))
                        {
                            isAMonteCarloTest = YES;
                            testType = TTHashMonteCarloTest;
                        }

                        else if ([aLine isMatchedByRegex:@"(Monte|MCT|Carlo)"])
                        {
                            isAMonteCarloTest = YES;
                            testType = TTCipherKnownAnswerTest;
                        }
                        else if ((cipherType == TFCipherSHA1)   ||
                                 (cipherType == TFCipherSHA224) ||
                                 (cipherType == TFCipherSHA256) ||
                                 (cipherType == TFCipherSHA384) ||
                                 (cipherType == TFCipherSHA512))
                        {
                            testType = TTHashKnownAnswerTest;
                        }
                        else if  (cipherType == TFCipherHMAC)    testType = TTHMAC;
                        else if  (cipherType == TFCipherDRBG)    testType = TTDRBG;
                        else                                     testType = TTCipherKnownAnswerTest;
                    }
                }

                if (cipherType == TFCipherRC4)
                    iv = [@"00000000000000000000000000000000" dataUsingEncoding:NSUTF8StringEncoding];

                if ([aLine isMatchedByRegex:@"^# Key Length.*?(128|192|256)"])
                {
                    if (cipherType != TFCipherAES)
                    {
                        NSString* keySize = [self getValueFromKeyValuePairString:aLine];
                        fprintf(stderr, "Error: Unexpected Key length [%s] given for cipher [%s]\n",
                                [keySize UTF8String],
                                [CipherTypeToString(cipherType) UTF8String]);

                        [pool drain];
                        return result;
                    }
                }


                //-----------------------------------------------------------------------------
                // Get the test data from each
                //-----------------------------------------------------------------------------
                if      ([aLine isMatchedByRegex:@"^(KEY|KEY1|Key) = (.*)"])    // Tests: RNG
                {
                    if (nil != key)
                    {
                        fprintf(stderr, "KEY seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    tempStr = [self getValueFromKeyValuePairString:aLine];
                    key     = HexStringToData(tempStr);

                    // Add the environment data to the cumulative "temptTestEnvironItems" array
                    if ((testType == TTCCMVADT) || (testType == TTCCMVPT) || (testType == TTCCMVTT) ||
                        (testType == TTCCMVNT)  || (testType == TTCCMDVPT))
                    {
                        [tempTestEnvironItems addObject:@""];
                        [tempTestEnvironItems addObject:aLine];
                    }
                }
                else if ([aLine isMatchedByRegex:@"^(KEYs) = (.*)"])            // Tests: RNG
                {
                    if (nil != key)
                    {
                        fprintf(stderr, "KEY seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    singleTDESKey   = YES;
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    key             = HexStringToData(tempStr);
                    key2            = [[key copy] autorelease];
                    key3            = [[key copy] autorelease];
                }
                else if ([aLine isMatchedByRegex:@"^KEY2 = (.*)"])              // Tests: TDES
                {
                    if (nil == key)
                    {
                        fprintf(stderr, "First key not set, but got second key - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    if (nil != key2)
                    {
                        fprintf(stderr, "KEY2 seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    singleTDESKey   = NO;
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    key2            = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^KEY3 = (.*)"])              // Tests: TDES
                {
                    if (nil == key2)
                    {
                        fprintf(stderr, "Second key not set, but got third key - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    if (nil != key3)
                    {
                        fprintf(stderr, "KEY3 seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    singleTDESKey   = NO;
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    key3            = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^IV = (.*)"])                // Tests: - multiple
                {
                    if (nil != iv)
                    {
                        fprintf(stderr, "IV seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    iv              = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^PLAINTEXT = (.*)"])         // Tests: - multiple
                {
                    if (nil != plainText)
                    {
                        fprintf(stderr, "PLAINTEXT/CIPHERTEXT seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    plainText       = HexStringToData(tempStr);
                    encryption      = YES;
                }
                else if ([aLine isMatchedByRegex:@"^CIPHERTEXT = (.*)"])        // Tests: - multiple
                {
                    if (nil != plainText)
                    {
                        fprintf(stderr, "PLAINTEXT/CIPHERTEXT seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    plainText       = HexStringToData(tempStr);
                    encryption      = NO;
                }
                else if ([aLine isMatchedByRegex:@"^CT = (.*)"])                // Tests: GCM
                {
                    if (nil != plainText)
                    {
                        fprintf(stderr, "PLAINTEXT/CIPHERTEXT seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    plainText       = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^PT = (.*)"])                // Tests: GCM
                {
                    if (nil != plainText)
                    {
                        fprintf(stderr, "PLAINTEXT/CIPHERTEXT seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    plainText       = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^AAD = (.*)"])               // Tests: GCM
                {
                    if (nil != aData)
                    {
                        fprintf(stderr, "AAD seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    aData           = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^Tag = (.*)"])               // Tests: GCM
                {
                    if (nil != tagData)
                    {
                        fprintf(stderr, "AAD seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    tagData         = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^Len = (.*)"])               // Tests: Hashes
                {
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    NSInteger tempValue = [tempStr integerValue];
                    length          = [NSNumber numberWithInteger:tempValue];
                }
                else if ([aLine isMatchedByRegex:@"^(Msg|Seed|CAVSHashZZ) = (.*)"])        // Tests: Hashes
                {
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    msg             = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^SHAAlg = (.*)"])            // Tests: RSA Sig
                {
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    shaAlgo         = [tempStr stringByTrimmingCharactersInSet:
                                       [NSCharacterSet whitespaceAndNewlineCharacterSet]];
                }
                else if ([aLine isMatchedByRegex:@"^n = (.*)"] )                // Tests: RSA Sig
                {
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    nData           = HexStringToData(tempStr);
                    nDataSeen       = YES;
                }
                else if ([aLine isMatchedByRegex:@"^e = (.*)"])                 // Tests: RSA Sig
                {
                    if ((nil != eData))         // Means we have a data set without a qrandom, so perform some voodoo
                    {
                        aData       = eData;    // Since qrandom missing, hold onto eData in aData temporarily
                                                // Holding previous eData in aData
                        testFound   = true;
                    }

                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    eData           = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^S = (.*)"])                 // Tests: RSA Sig
                {
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    sData           = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^DT = (.*)"])                // Tests: X9.31 RNG
                {
                    if (nil != dtData)
                    {
                        fprintf(stderr, "DT seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    dtData          = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^V = (.*)"])                 // Tests: X9.31 RNG
                {
                    if (nil != vData)
                    {
                        fprintf(stderr, "V seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    vData           = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^Klen = (.*)"])              // Tests: HMAC RNG
                {
                    if (nil != klen)
                    {
                        fprintf(stderr, "Klen seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    NSInteger tempValue = [tempStr integerValue];
                    klen            = [NSNumber numberWithInteger:tempValue];
                }
                else if ([aLine isMatchedByRegex:@"^Tlen = (.*)"])              // Tests: HMAC RNG
                {
                    if (nil != tlen)
                    {
                        fprintf(stderr, "Tlen seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr             = [self getValueFromKeyValuePairString:aLine];
                    NSInteger tempValue = [tempStr integerValue];
                    tlen                = [NSNumber numberWithInteger:tempValue];

                    if (!testFound) {
                        [tempTestEnvironItems addObject:aLine];
                    }
                }
                else if ([aLine isMatchedByRegex:@"^N = (.*)"])                 // Tests: DSA PQGGen
                {
                    if (TFCipherECC == cipherType)                              // -- for ECC
                    {
                        if (nil != nValue)
                        {
                            fprintf(stderr, "N seen twice - input file junk\n");
                            [pool drain];
                            return result;
                        }
                        tempStr     = [self getValueFromKeyValuePairString:aLine];
                        NSInteger tempValue = [tempStr integerValue];
                        nValue      = [NSNumber numberWithInteger:tempValue];
                    }
                    if (TFCipherRSA == cipherType)                              // -- for RSA
                    {
                        if (nil != nValue)
                        {
                            fprintf(stderr, "N seen twice - input file junk\n");
                            [pool drain];
                            return result;
                        }
                        tempStr     = [self getValueFromKeyValuePairString:aLine];
                        NSInteger tempValue = [tempStr integerValue];
                        nValue      = [NSNumber numberWithInteger:tempValue];
                    }
                    else                                                        // -- for other
                    {
                        if (nil != capitalNData)
                        {
                            fprintf(stderr, "Capital N seen twice - input file junk\n");
                            [pool drain];
                            return result;
                        }
                        tempStr     = [self getValueFromKeyValuePairString:aLine];
                        capitalNData = HexStringToData(tempStr);
                    }
                }
                else if ([aLine isMatchedByRegex:@"^P = (.*)"])                 // Tests: DSA SigVer
                {
                    if (TTFFDHFunction == testType || TTFFDHValidity == testType)
                    {
                        [tempTestEnvironItems addObject:aLine];
                    }
                    else if (nil != capitalPData)
                    {
                        fprintf(stderr, "P seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];

                    if ((TTAESKeyWrap == testType) || (TTAESKeyWrapPad == testType))
                    {
                        if (nil != plainText)
                        {
                            fprintf(stderr, "PLAINTEXT seen twice - input file junk\n");
                            [pool drain];
                            return result;
                        }

                        tempStr = [self getValueFromKeyValuePairString:aLine];
                        plainText = HexStringToData(tempStr);
                    }
                    else    capitalPData = HexStringToData(tempStr);

                }
                else if ([aLine isMatchedByRegex:@"^Q = (.*)"])                 // Tests: DSA SigVer
                {
                    if (TTFFDHFunction == testType || TTFFDHValidity == testType)
                    {
                        [tempTestEnvironItems addObject:aLine];
                    }
                    else if (nil != capitalQData)
                    {
                        fprintf(stderr, "Q seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    capitalQData    = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^G = (.*)"])                 // Tests: DSA SigVer
                {
                    if (TTFFDHFunction == testType || TTFFDHValidity == testType)
                    {
                        [tempTestEnvironItems addObject:aLine];
                    }
                    else if (nil != capitalGData)
                    {
                        fprintf(stderr, "G seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    capitalGData    = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^Y = (.*)"] ||
                        [aLine isMatchedByRegex:@"^YephemCAVS = (.*)"])         // Tests: DSA SigVer
                {
                    if (nil != capitalYData)
                    {
                        fprintf(stderr, "Y seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    capitalYData    = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^R = (.*)"])                 // Tests: DSA SigVer
                {
                    if (nil != capitalRData)
                    {
                        fprintf(stderr, "R seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    capitalRData    = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^xp1 = (.*)"] ||
                        [aLine isMatchedByRegex:@"^XephemIUT = (.*)"])               // Tests: RSA KeyGen
                {
                    if (nil != xp1)
                    {
                        fprintf(stderr, "xp1 seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    xp1         = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^xp2 = (.*)"] ||
                        [aLine isMatchedByRegex:@"^YephemIUT = (.*)"])               // Tests: RSA KeyGen
                {
                    if (nil != xp2)
                    {
                        fprintf(stderr, "xp2 seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    xp2         = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^Xp = (.*)"])                // Tests: RSA KeyGen
                {
                    if (nil != xp)
                    {
                        fprintf(stderr, "Xp seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    xp          = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^xq1 = (.*)"])               // Tests: RSA KeyGen
                {
                    if (nil != xq1)
                    {
                        fprintf(stderr, "xq1 seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    xq1         = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^xq2 = (.*)"])               // Tests: RSA KeyGen
                {
                    if (nil != xq2)
                    {
                        fprintf(stderr, "xq2 seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    xq2         = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^Xq = (.*)"])                // Tests: RSA KeyGen
                {
                    if (nil != xq)
                    {
                        fprintf(stderr, "Xq seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    xq          = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^prandom = (.*)"])           // Tests: RSA KeyGen
                {
                    if (nil != prnd)
                    {
                        fprintf(stderr, "prandom seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    prnd        = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^qrandom = (.*)"])           // Tests: RSA KeyGen
                {
                    if (nil != qrnd)
                    {
                        fprintf(stderr, "qrandom seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    qrnd        = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^K = (.*)"])                 // Tests: AES-KW, AES-KWP
                {
                    if (nil != key)
                    {
                        fprintf(stderr, "K seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    key         = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^C = (.*)"])                 // Tests: AES-KW, AES-KWP
                {
                    if (nil != plainText)
                    {
                        fprintf(stderr, "CIPHERTEXT seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr = [self getValueFromKeyValuePairString:aLine];
                    plainText = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^EntropyInput = (.*)"])      // Tests: DRBG
                {
                    if (nil != entropyInput)
                    {
                        fprintf(stderr, "entropyInput seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    entropyInput    = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^Nonce = (.*)"])             // Tests: DRBG
                {
                    if (nil != nonce)
                    {
                        fprintf(stderr, "nonce seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    nonce           = HexStringToData(tempStr);

                    // Add the environment data to the cumulative "temptTestEnvironItems" array
                    if ((testType == TTCCMVADT) || (testType == TTCCMVPT) || (testType == TTCCMVTT))
                        [tempTestEnvironItems addObject:aLine];
                }
                else if ([aLine isMatchedByRegex:@"^PersonalizationString = (.*)"]) // Tests: DRBG
                {
                    if (nil != personalizationString)
                    {
                        fprintf(stderr, "personalizationString seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    tempStr                 = [self getValueFromKeyValuePairString:aLine];
                    personalizationString   = HexStringToData(tempStr);
                    if (nil == personalizationString)   personalizationString = [NSData data];
                }
                else if ([aLine isMatchedByRegex:@"^Qx = (.*)"])                // Tests: ECDH
                {
                    if (nil != qX)
                    {
                        fprintf(stderr, "qX seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    qX          = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^Qy = (.*)"])                // Tests: ECDH
                {
                    if (nil != qY)
                    {
                        fprintf(stderr, "qY seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    qY          = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^QeCAVSx = (.*)"])           // Tests: ECDH
                {
                    if (nil != QeX)
                    {
                        fprintf(stderr, "QeX seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    QeX         = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^QeCAVSy = (.*)"])           // Tests: ECDH
                {
                    if (nil != QeY)
                    {
                        fprintf(stderr, "QeY seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    QeY         = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^deIUT = (.*)"])             // Tests: ECDH
                {
                    if (nil != deIUT)
                    {
                        fprintf(stderr, "deIUT seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    deIUT       = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^QeIUTx = (.*)"])            // Tests: ECDH
                {
                    if (nil != QeIUTx)
                    {
                        fprintf(stderr, "QeIUTx seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    QeIUTx      = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^QeIUTy = (.*)"])            // Tests: ECDH
                {
                    if (nil != QeIUTy)
                    {
                        fprintf(stderr, "QeIUTy seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    QeIUTy      = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^QsCAVSx = (.*)"])           // Tests: ECDH
                {
                    if (nil != QsX)
                    {
                        fprintf(stderr, "QsX seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    QsX         = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^QsCAVSy = (.*)"])           // Tests: ECDH
                {
                    if (nil != QsY)
                    {
                        fprintf(stderr, "QsY seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    QsY         = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^dsIUT = (.*)"])             // Tests: ECDH
                {
                    if (nil != dsIUT)
                    {
                        fprintf(stderr, "dsIUT seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    dsIUT       = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^QsIUTx = (.*)"])            // Tests: ECDH
                {
                    if (nil != QsIUTx)
                    {
                        fprintf(stderr, "QsIUTx seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    QsIUTx      = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^QsIUTy = (.*)"])            // Tests: ECDH
                {
                    if (nil != QsIUTy)
                    {
                        fprintf(stderr, "QsIUTy seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    QsIUTy      = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^CAVSHashZZ = (.*)"])        // Tests: ECDH
                {
                    if (nil != HashZZ)
                    {
                        fprintf(stderr, "CAVSHashZZ seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    HashZZ      = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^CAVSTag = (.*)"])           // Tests: ECDH
                {
                    if (nil != CAVSTag)
                    {
                        fprintf(stderr, "CAVSTag seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    CAVSTag     = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^OI = (.*)"])                // Tests: ECDH
                {
                    if (nil != OI)
                    {
                        fprintf(stderr, "OI seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr     = [self getValueFromKeyValuePairString:aLine];
                    OI          = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^DataUnitSeqNumber = (.*)"]) // Tests:
                {
                    if (nil != dataUnitSeqNumber)
                    {
                        fprintf(stderr, "dataUnitSeqNumber seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    else
                    {
                        tempStr             = [self getValueFromKeyValuePairString:aLine];
                        NSInteger tempValue = [tempStr integerValue];
                        dataUnitSeqNumber   = [NSNumber numberWithInteger:tempValue];
                    }
                }
                else if ([aLine isMatchedByRegex:@"^DataUnitLen = (.*)"])       // Tests:
                {
                    if (nil != dataUnitSeqNumber)
                    {
                        fprintf(stderr, "dataUnitLen seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    else
                    {
                        tempStr             = [self getValueFromKeyValuePairString:aLine];
                        NSInteger tempValue = [tempStr integerValue];
                        dataUnitLen         = [NSNumber numberWithInteger:tempValue];
                    }
                }
                else if ([aLine isMatchedByRegex:@"^Static-PrivateKey = (.*)"]) // Tests:  Curve25519-ECDH
                {
                    if (nil != classBStaticPrivKey)
                    {
                        fprintf(stderr, "ClassB-Static-PrivateKey seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    else
                    {
                        tempStr             = [self getValueFromKeyValuePairString:aLine];
                        classBStaticPrivKey = HexStringToData(tempStr);
                    }
                }
                else if ([aLine isMatchedByRegex:@"^Static-PublicKey = (.*)"])  // Tests:  Curve25519-ECDH
                {
                    if (nil != classBStaticPubKey)
                    {
                        fprintf(stderr, "ClassB-Static-PublicKey seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    else
                    {
                        tempStr             = [self getValueFromKeyValuePairString:aLine];
                        classBStaticPubKey  = HexStringToData(tempStr);
                    }
                }
                else if ([aLine isMatchedByRegex:@"^Ephemeral-PrivateKey = (.*)"])  // Tests:  Curve25519-ECDH
                {
                    if (nil != classBEphemPrivKey)
                    {
                        fprintf(stderr, "ClassB-Ephemeral-PrivateKey seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    else
                    {
                        tempStr             = [self getValueFromKeyValuePairString:aLine];
                        classBEphemPrivKey  = HexStringToData(tempStr);
                    }
                }
                else if ([aLine isMatchedByRegex:@"^Ephemeral-PublicKey = (.*)"])   // Tests:  Curve25519-ECDH
                {
                    if (nil != classBEphemPubKey)
                    {
                        fprintf(stderr, "ClassB-Ephemeral-PublicKey seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    else
                    {
                        tempStr             = [self getValueFromKeyValuePairString:aLine];
                        classBEphemPubKey   = HexStringToData(tempStr);
                    }
                }
                else if ([aLine isMatchedByRegex:@"^Shared-Secret = (.*)"])       // Tests:  Curve25519-ECDH
                {
                    if (nil != classBSharedSecret)
                    {
                        fprintf(stderr, "Shared-Secret seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    else
                    {
                        tempStr             = [self getValueFromKeyValuePairString:aLine];
                        classBSharedSecret  = HexStringToData(tempStr);
                    }
                }
                else if ([aLine isMatchedByRegex:@"^Plen = (.*)"])              // Tests: AES-CCM
                {
                    if (nil != plen)
                    {
                        fprintf(stderr, "Plen seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    NSInteger tempValue = [tempStr integerValue];
                    plen            = [NSNumber numberWithInteger:tempValue];

                    if (!testFound) {
                        [tempTestEnvironItems addObject:aLine];
                    }
                }
                else if ([aLine isMatchedByRegex:@"^Nlen = (.*)"])              // Tests: AES-CCM
                {
                    if (nil != nlen)
                    {
                        fprintf(stderr, "Nlen seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    NSInteger tempValue = [tempStr integerValue];
                    nlen            = [NSNumber numberWithInteger:tempValue];

                    if (!testFound) {
                        [tempTestEnvironItems addObject:aLine];
                    }
                }
                else if ([aLine isMatchedByRegex:@"^Alen = (.*)"])              // Tests: AES-CCM
                {
                    if (nil != alen)
                    {
                        fprintf(stderr, "Alen seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }
                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    NSInteger tempValue = [tempStr integerValue];
                    alen            = [NSNumber numberWithInteger:tempValue];

                    if (!testFound) {
                        [tempTestEnvironItems addObject:aLine];
                    }
                }
                else if ([aLine isMatchedByRegex:@"^Adata = (.*)"])             // Tests: AES-CCM
                {
                    if (nil != aData)
                    {
                        fprintf(stderr, "Adata seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    aData           = HexStringToData(tempStr);
                }
                else if ([aLine isMatchedByRegex:@"^Payload = (.*)"])           // Tests: AES-CCM
                {
                    if (nil != plainText)
                    {
                        fprintf(stderr, "Payload seen twice - input file junk\n");
                        [pool drain];
                        return result;
                    }

                    tempStr         = [self getValueFromKeyValuePairString:aLine];
                    plainText       = HexStringToData(tempStr);
                }

                else
                {
                    if (predictionResistance)                                   // Prediction Resistence!
                    {
                        if ([aLine isMatchedByRegex:@"^AdditionalInput = (.*)"])  // Tests: DRBG
                        {
                            if (nil == additionalInput) additionalInput = [NSMutableArray array];

                            tempStr = [self getValueFromKeyValuePairString:aLine];
                            if (nil == tempStr || 0 == [tempStr length])
                                [additionalInput addObject:[NSData data]];
                            else
                                [additionalInput addObject:HexStringToData(tempStr)];
                        }
                        if ([aLine isMatchedByRegex:@"^EntropyInputPR = (.*)"])   // Tests: DRBG
                        {
                            if (nil == additionalEntropyInput) additionalEntropyInput = [NSMutableArray array];

                            tempStr = [self getValueFromKeyValuePairString:aLine];
                            if (nil == tempStr || 0 == [tempStr length])
                                [additionalEntropyInput addObject:[NSData data]];
                            else
                                [additionalEntropyInput addObject:HexStringToData(tempStr)];
                        }
                    }
                    else                                                        // NO Prediction Resistence!
                    {
                        if ([aLine isMatchedByRegex:@"^AdditionalInput = (.*)"])        // Tests: DRBG
                        {
                            if (nil == additionalInput)     additionalInput = [NSMutableArray array];

                            tempStr = [self getValueFromKeyValuePairString:aLine];
                            if (nil == tempStr || 0 == [tempStr length])
                                [additionalInput addObject:[NSData data]];
                            else
                                [additionalInput addObject:HexStringToData(tempStr)];
                        }
                        if ([aLine isMatchedByRegex:@"^EntropyInputReseed = (.*)"])     // Tests: DRBG
                        {
                            if (nil == additionalEntropyInput)  additionalEntropyInput = [NSMutableArray array];

                            tempStr = [self getValueFromKeyValuePairString:aLine];
                            if (nil == tempStr || 0 == [tempStr length])
                                [additionalEntropyInput addObject:[NSData data]];
                            else
                                [additionalEntropyInput addObject:HexStringToData(tempStr)];
                        }
                        if ([aLine isMatchedByRegex:@"^AdditionalInputReseed = (.*)"])  // Tests: DRBG
                        {
                            if (nil == additionalEntropyInput)      additionalEntropyInput = [NSMutableArray array];

                            tempStr = [self getValueFromKeyValuePairString:aLine];
                            if (nil == tempStr || 0 == [tempStr length])
                                [additionalEntropyInput addObject:[NSData data]];
                            else
                                [additionalEntropyInput addObject:HexStringToData(tempStr)];
                        }
                    }
                }
            }

            //
            // Check to see if we have enough data to make a test object
            // if we do, then build the test object
            //
            if (testType == TTUnknownTestType)  continue;


            TestFileData* aTest = nil;

            switch (testType)
            {
                case TTCipherKnownAnswerTest:                   // KAT - Known Answer Test
                {   // Ensure we have all parameters
                    if (nil != key && nil != plainText && cipherType != TFCipherUnknown)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        [aTest setKey:key];
                        [aTest setKey2:key2];
                        [aTest setKey3:key3];
                        [aTest setPlainText:plainText];
                        [aTest setCipherType:cipherType];
                        [aTest setIv:iv];
                        aTest.encryption    = encryption;
                        aTest.modeType      = modeType;
                        aTest.monteCarlo    = isAMonteCarloTest;
                        aTest.numKeys       = numKeysValue;
                        aTest.singleTDESKey = singleTDESKey;
                        aTest.aesImplType   = aesImplType;

                        // Clear repeat values for next round of data gathering
                        key         = nil;
                        key2        = nil;
                        key3        = nil;
                        iv          = nil;
                        plainText   = nil;
                    }
                }
                    break;

                case TTCipherMonteCarloTest:                    // MCT - Monte Carlo Test
                {   // Ensure we have all parameters
                    if (nil != key && nil != plainText && cipherType != TFCipherUnknown)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        [aTest setKey:key];
                        [aTest setKey2:key2];
                        [aTest setKey3:key3];
                        [aTest setPlainText:plainText];
                        [aTest setCipherType:cipherType];
                        [aTest setIv:iv];
                        aTest.encryption    = encryption;
                        aTest.modeType      = modeType;
                        aTest.monteCarlo    = isAMonteCarloTest;
                        aTest.numKeys       = numKeysValue;
                        aTest.singleTDESKey = singleTDESKey;
                        aTest.aesImplType   = aesImplType;

                        // Clear repeat values for next round of data gathering
                        key         = nil;
                        key2        = nil;
                        key3        = nil;
                        iv          = nil;
                        plainText   = nil;
                    }
                }
                    break;

                case TTHashKnownAnswerTest:                     // HASH KAT - Known Answer Test
                {   // Ensure we have all parameters
                    if (nil != msg && cipherType != TFCipherUnknown)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.msg       = msg;
                        [aTest setCipherType:cipherType];
                        aTest.length    = length;

                        // Clear repeat values for next round of data gathering
                        msg         = nil;
                        length      = nil;
                    }
                }
                    break;

                case TTHashMonteCarloTest:                      // HASH MCT - Monte Carlo Test
                {   // Ensure we have all parameters
                    if (nil != msg && cipherType != TFCipherUnknown)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.msg           = msg;
                        aTest.monteCarlo    = isAMonteCarloTest;
                        [aTest setCipherType:cipherType];

                        // Clear repeat values for next round of data gathering
                        msg         = nil;
                    }
                }
                    break;

                case TTRSASignatureGeneration:                  // RSA SigGen - Signature Generation
                {   // Ensure we have all parameters
                    if (nil != rsaKeySize && nil != msg && nil != shaAlgo )
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        [aTest setCipherType:TFCipherRSA];
                        [aTest setTestType:TTRSASignatureGeneration];
                        aTest.rsaKeySize    = rsaKeySize;
                        aTest.msg           = msg;
                        aTest.shaAlgo       = StringToCipherType(shaAlgo);
                        aTest.rsaSigType    = rsaSigType;

                        // Clear repeat values for next round of data gathering
                        // NOTE:  rsaKeySize is not reset
                        //        eData will be set as needed.
                        msg         = nil;
                        shaAlgo     = nil;
                    }
                }
                    break;

                case TTRSASignatureVerification:                // RSA SigGen - Signature Verification
                {   // Ensure we have all parameters
                    if (nil != rsaKeySize && nil !=  shaAlgo &&
                        nil != msg && nil != sData &&
                        nil != eData && nil != nData)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];

                        [aTest setCipherType:TFCipherRSA];
                        [aTest setTestType:TTRSASignatureVerification];
                        aTest.msg           = msg;
                        aTest.rsaKeySize    = rsaKeySize;
                        aTest.shaAlgo       = StringToCipherType(shaAlgo);
                        aTest.sData         = sData;
                        aTest.eData         = eData;
                        aTest.nData         = nData;
                        aTest.printNData    = nDataSeen;
                        aTest.rsaSigType    = rsaSigType;

                        // Clear repeat values for next round of data gathering
                        msg         = nil;
                        shaAlgo     = nil;
                        eData       = nil;
                        sData       = nil;
                        nDataSeen   = NO;
                    }

                }
                    break;

                case TTRNGKAT:                                  // RNG KAT - Known Answer Test
                {   // Ensure we have all parameters
                    if (nil != key && nil != dtData && nil != vData)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        [aTest setKey:key];
                        [aTest setDtData:dtData];
                        [aTest setVData:vData];
                        aTest.numKeys       = numKeysValue;
                        aTest.singleTDESKey = singleTDESKey;

                        // Clear repeat values for next round of data gathering
                        key         = nil;
                        dtData      = nil;
                        vData       = nil;
                    }
                }
                    break;

                case TTRNGMCT:                                  // RNG MCT - Monte Carlo Test
                {   // Ensure we have all parameters
                    if (nil != key && nil != dtData && nil != vData)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        [aTest setKey:key];
                        [aTest setDtData:dtData];
                        [aTest setVData:vData];
                        aTest.numKeys       = numKeysValue;
                        aTest.singleTDESKey = singleTDESKey;

                        // Clear repeat values for next round of data gathering
                        key         = nil;
                        dtData      = nil;
                        vData       = nil;
                    }
                }
                    break;

                case TTHMAC:                                    // HMAC
                {   // Ensure we have all parameters
                    if (nil != klen && nil != tlen && nil != key && nil != msg)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        [aTest setCipherType:cipherType];
                        [aTest setKlen:klen];
                        [aTest setTlen:tlen];
                        [aTest setKey:key];
                        aTest.msg           = msg;
                        aTest.singleTDESKey = singleTDESKey;

                        // Clear repeat values for next round of data gathering
                        key         = nil;
                        tlen        = nil;
                        klen        = nil;
                        msg         = nil;
                    }
                }
                    break;

                case TTDSAPQGGen:                               // DSA PQG Generation
                {   // Ensure we have all parameters
                    if (rsaKeySize != nil && nil != capitalNData)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        [aTest setCapitalNData:capitalNData];

                        // Clear repeat values for next round of data gathering
                        // NOTE:  rsaKeySize is not reset
                        capitalNData = nil;
                    }
                }
                    break;

                case TTRSAKeyGeneration:                        // RSA Key Generation
                {

                    if (rsaKeyGenType == TRSAKeyGenTypeProbPrimeWithCondition)
                    {   // Ensure we have all parameters
                        if ((nil != rsaKeySize) && (nil != numKeysValue))
                        {
                            // Setup for RSA KeyGen using Probable Primes ....
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType    = cipherType;
                            aTest.testType      = testType;
                            aTest.rsaKeySize    = rsaKeySize;
                            aTest.rsaKeyGenType = rsaKeyGenType;
                            aTest.numKeys       = numKeysValue;

                            // Clear repeat values for next round of data gathering
                            rsaKeySize          = nil;
                            numKeysValue        = nil;
                        }
                    }
                    else if (rsaKeyGenType == TRSAKeyGenTypeRandProbPrime)
                    {   // Ensure we have all parameters
                        if ((nil != rsaKeySize) && (nil != numKeysValue))
                        {
                            // Setup for RSA KeyGen using Random Probable Primes ....
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType    = cipherType;
                            aTest.testType      = testType;
                            aTest.rsaKeySize    = rsaKeySize;
                            aTest.rsaKeyGenType = rsaKeyGenType;
                            aTest.numKeys       = numKeysValue;

                            // Clear repeat values for next round of data gathering
                            rsaKeySize          = nil;
                            numKeysValue        = nil;
                            nValue              = nil;
                        }
                    }
                    else if (rsaKeyGenType == TRSAKeyGenTypeRandProbPrimeKAT)
                    {   // Ensure we have all parameters
                        if ((nil != prnd) && (nil != qrnd) && (nil != eData))
                        {
                            // Setup for RSA KeyGen using Random Probable Primes KAT ....
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType    = cipherType;
                            aTest.testType      = testType;
                            aTest.rsaKeySize    = rsaKeySize;
                            aTest.rsaKeyGenType = rsaKeyGenType;
                            aTest.prnd          = prnd;
                            aTest.qrnd          = qrnd;
                            aTest.eData         = eData;

                            // Clear repeat values for next round of data gathering
                            prnd                = nil;
                            qrnd                = nil;
                            eData               = nil;

                        }    // Ensure we have all parameters
                        else if ((nil != prnd) && (nil == qrnd) && (nil != aData))
                        {
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType    = cipherType;
                            aTest.testType      = testType;
                            aTest.rsaKeySize    = rsaKeySize;
                            aTest.rsaKeyGenType = rsaKeyGenType;
                            aTest.prnd          = prnd;
                            NSString *Zeros     = @"";
                            for (int i=0;i<[prnd length]*2;i++) Zeros = [Zeros stringByAppendingString:@"0"];
                            aTest.qrnd          = HexStringToData(Zeros);

                            aTest.eData = aData; // recall, we stored eData momentarily in aData

                            // Clear repeat values for next round of data gathering
                            prnd        = nil;
                            qrnd        = nil;
                            aData       = nil;   // Clear aData; eData already has value for next test data set

                        }
                    }

                    // Clear repeat values for next round of data gathering
                    nValue = nil;
                }
                    break;

                case TTDRBG:                                    // DRBG
                {   // Ensure we have all parameters
                    if (nil != entropyInput             &&/*nil != nonce                    && */
                        nil != personalizationString    &&  nil != additionalInput          &&
                        2 == [additionalInput count]    &&  nil != additionalEntropyInput   &&
                        2 == [additionalEntropyInput count])
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType              = testType;
                        aTest.entropyInput          = entropyInput;
                        aTest.nonce                 = nonce;
                        aTest.personalizationString = personalizationString;
                        aTest.additionalInput       = additionalInput;
                        aTest.additionalEntropyInput= additionalEntropyInput;
                        aTest.predictionResistance  = predictionResistance;
                        aTest.cipherType            = cipherType;

                        // Clear repeat values for next round of data gathering
                        entropyInput            = nil;
                        nonce                   = nil;
                        personalizationString   = nil;
                        additionalInput         = nil;
                        additionalEntropyInput  = nil;
                    }
                }
                    break;

                case TTHMACDRBG:                                    // HMAC-DRBG
                {   // Ensure we have all parameters
                    if (nil != entropyInput             &&  nil != nonce                    &&
                        nil != personalizationString    &&  (nil != additionalEntropyInput || !predictionResistance)   &&
                        nil != additionalInput          &&  2 == [additionalInput count])
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        [aTest setTestType:TTHMACDRBG];
                        aTest.entropyInput          = entropyInput;
                        aTest.nonce                 = nonce;
                        aTest.personalizationString = personalizationString;
                        aTest.additionalEntropyInput = additionalEntropyInput;
                        aTest.additionalInput       = additionalInput;
                        aTest.predictionResistance  = predictionResistance;
                        aTest.cipherType            = cipherType;
                        aTest.returnedBitsLen       = returnedBitsLen;
                        
                        // Clear repeat values for next round of data gathering
                        entropyInput            = nil;
                        nonce                   = nil;
                        personalizationString   = nil;
                        additionalInput         = nil;
                        additionalEntropyInput  = nil;
                    }
                }
                    break;

                case TTGCM:                                     // GCM
                {   // Ensure we have all parameters
                    if (nil != key   && nil != ptLength && nil != aadLength &&
                        nil != ivLen && nil != tagLength)
                    {
                        // if this is for Encryption then we have all of the necessary
                        // data otherwise we may need more
                        if (!encryption)    // Decryption
                        {
                            if ([ivLen intValue]     > 0 && iv          == nil)     break;
                            if ([ptLength intValue]  > 0 && plainText   == nil)     break;
                            if ([aadLength intValue] > 0 && aData       == nil)     break;
                            if ([tagLength intValue] > 0 && tagData     == nil)     break;
                        }
                        else                // Encryption
                        {
                            if ([ptLength intValue]  > 0 && plainText == nil)       break;
                            if ([aadLength intValue] > 0 && aData     == nil)       break;
                        }

                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.cipherType    = cipherType;
                        aTest.key           = key;
                        aTest.plainText     = plainText;
                        aTest.iv            = iv;
                        aTest.encryption    = encryption;
                        aTest.monteCarlo    = false;
                        aTest.aData         = aData;
                        aTest.ivLen         = ivLen;
                        aTest.tagLength     = tagLength;
                        aTest.tag           = tagData;
                        aTest.testType      = TTGCM;
                        aTest.aesImplType   = aesImplType;

                        // Clear repeat values for next round of data gathering
                        // NOTE:   ivLen and tagLength -- only reset when they change
                        key         = nil;
                        iv          = nil;
                        plainText   = nil;
                        aData       = nil;
                        tagData     = nil;
                    }
                }
                    break;

                case TTCCMVADT:                                 // AES-CCM VADT
                {   // Ensure we have all parameters

                    if (nil != aData        && nil != plainText     &&
                        nil != key          && nil != nonce         && nil != plen  &&
                        nil != nlen         && nil != tlen          && nil != alen)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType      = TTCCMVADT;        //  TTCCMVADT
                        aTest.cipherType    = cipherType;       //  AES
                        aTest.length        = length;           //  128|192|256
                        aTest.encryption    = encryption;       //  true|false
                        aTest.monteCarlo    = false;            //  Definitely not a Monte Carlo Test
                        aTest.aesImplType   = aesImplType;      //  AES Normal Implementation
                        aTest.plen          = plen;             //  "Plen   = "
                        aTest.nlen          = nlen;             //  "Nlen   = "
                        aTest.tlen          = tlen;             //  "Tlen   = "
                        aTest.alen          = alen;             //  "Alen   = "
                        aTest.key           = key;              //  "Key    = "
                        aTest.nonce         = nonce;            //  "Nonce  = "

                        aTest.aData         = aData;            //  "Adata  = "
                        aTest.plainText     = plainText;        //  "Payload = "

                        // Clear repeat values for next round of data gathering
                        aData               = nil;
                        plainText           = nil;
                    }
                }
                    break;

                case TTCCMVNT:                                  // AES-CCM VNT
                {   // Ensure we have all parameters

                    if (nil != aData        && nil != plainText     &&
                        nil != key          && nil != nonce         && nil != plen &&
                        nil != nlen         && nil != tlen          && nil != alen)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType      = TTCCMVNT;         //  TTCCMVNT
                        aTest.cipherType    = cipherType;       //  AES
                        aTest.length        = length;           //  128|192|256
                        aTest.encryption    = encryption;       //  true | false
                        aTest.monteCarlo    = false;            //  Definitely not a Monte Carlo Test
                        aTest.aesImplType   = TAESIMPLNormal;   //  AES Normal Implementation
                        aTest.plen          = plen;             //  "Plen   = "
                        aTest.nlen          = nlen;             //  "Nlen   = "
                        aTest.tlen          = tlen;             //  "Tlen   = "
                        aTest.alen          = alen;             //  "Alen   = "
                        aTest.key           = key;              //  "Key    = "

                        aTest.nonce         = nonce;            //  "Nonce  = "
                        aTest.aData         = aData;            //  "Adata  = "
                        aTest.plainText     = plainText;        //  "Payload = "

                        // Clear repeat values for next round of data gathering
                        nonce               = nil;
                        aData               = nil;
                        plainText           = nil;
                    }
                }
                    break;

                case TTCCMVPT:                                  // AES-CCM VPT
                {   // Ensure we have all parameters

                    if (nil != aData        && nil != plainText     &&
                        nil != key          && nil != nonce         && nil != plen &&
                        nil != nlen         && nil != tlen          && nil != alen)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType      = TTCCMVPT;         //  TTCCMVPT
                        aTest.cipherType    = cipherType;       //  AES
                        aTest.length        = length;           //  128|192|256
                        aTest.encryption    = encryption;       //  true | false
                        aTest.monteCarlo    = false;            //  Definitely not a Monte Carlo Test
                        aTest.aesImplType   = TAESIMPLNormal;   //  AES Normal Implementation
                        aTest.plen          = plen;             //  "Plen   = "
                        aTest.nlen          = nlen;             //  "Nlen   = "
                        aTest.tlen          = tlen;             //  "Tlen   = "
                        aTest.alen          = alen;             //  "Alen   = "
                        aTest.key           = key;              //  "Key    = "
                        aTest.nonce         = nonce;            //  "Nonce  = "

                        aTest.aData         = aData;            //  "Adata  = "
                        aTest.plainText     = plainText;        //  "Payload = "

                        // Clear repeat values for next round of data gathering
                        aData               = nil;
                        plainText           = nil;
                    }
                }
                    break;

                case TTCCMVTT:                                  // AES-CCM VTT
                {   // Ensure we have all parameters

                    if (nil != aData        && nil != plainText     &&
                        nil != key          && nil != nonce         && nil != plen &&
                        nil != nlen         && nil != tlen          && nil != alen)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType      = TTCCMVTT;         //  TTCCMVTT
                        aTest.cipherType    = cipherType;       //  AES
                        aTest.length        = length;           //  128|192|256
                        aTest.encryption    = encryption;       //  true | false
                        aTest.monteCarlo    = false;            //  Definitely not a Monte Carlo Test
                        aTest.aesImplType   = TAESIMPLNormal;   //  AES Normal Implementation
                        aTest.plen          = plen;             //  "Plen   = "
                        aTest.nlen          = nlen;             //  "Nlen   = "
                        aTest.tlen          = tlen;             //  "Tlen   = "
                        aTest.alen          = alen;             //  "Alen   = "
                        aTest.key           = key;              //  "Key    = "
                        aTest.nonce         = nonce;            //  "Nonce  = "

                        aTest.aData         = aData;            //  "Adata  = "
                        aTest.plainText     = plainText;        //  "Payload = "

                        // Clear repeat values for next round of data gathering
                        aData               = nil;
                        plainText           = nil;
                    }
                }
                    break;

                case TTCCMDVPT:                                  // AES-CCM DVPT
                {   // Ensure we have all parameters

                    if (nil != aData        && nil != plainText     &&
                        nil != key          && nil != nonce         && nil != plen &&
                        nil != nlen         && nil != tlen          && nil != alen)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType      = TTCCMDVPT;        //  TTCCMDVPT
                        aTest.cipherType    = cipherType;       //  AES
                        aTest.length        = length;           //  128|192|256
                        aTest.encryption    = encryption;       //  true | false
                        aTest.monteCarlo    = false;            //  Definitely not a Monte Carlo Test
                        aTest.aesImplType   = TAESIMPLNormal;   //  AES Normal Implementation
                        aTest.plen          = plen;             //  "Plen   = "
                        aTest.nlen          = nlen;             //  "Nlen   = "
                        aTest.tlen          = tlen;             //  "Tlen   = "
                        aTest.alen          = alen;             //  "Alen   = "
                        aTest.key           = key;              //  "Key    = "

                        aTest.nonce         = nonce;            //  "Nonce  = "
                        aTest.aData         = aData;            //  "Adata  = "
                        aTest.plainText     = plainText;        //  "Payload = "

                        // Clear repeat values for next round of data gathering
                        nonce               = nil;
                        aData               = nil;
                        plainText           = nil;
                    }
                }
                    break;

                case TTXTS:                                     // XTS
                {   // Ensure we have all parameters
                    if (nil != key && nil != dataUnitSeqNumber && nil != dataUnitLen && nil != plainText)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.key               = key;
                        aTest.dataUnitSeqNumber = dataUnitSeqNumber;
                        aTest.dataUnitLen       = dataUnitLen;
                        aTest.plainText         = plainText;
                        aTest.testType          = TTXTS;
                        aTest.encryption        = encryption;
                        aTest.monteCarlo        = false;
                        aTest.cipherType        = TFCipherAES;

                        // Clear repeat values for next round of data gathering
                        key                     = nil;
                        dataUnitSeqNumber       = nil;
                        plainText               = nil;
                    }
                }
                    break;

                case TTECKeyGeneration:                         // EC Key Generation
                {   // Ensure we have all parameters
                    if (nil != curve && nil != nValue)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.nValue        = nValue;
                        aTest.curve         = curve;
                        aTest.cipherType    = cipherType;
                        aTest.testType      = TTECKeyGeneration;
                        aTest.ecKeyGenType  = ecKeyGenType;

                        // Clear repeat values for next round of data gathering
                        nValue              = nil;
                        capitalNData        = nil;
                    }
                }
                    break;

                case TTECSignatureGeneration:                   // EC Signature Generation
                {   // Ensure we have all parameters
                    if (nil != curve && nil != msg)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.curve         = curve;
                        aTest.cipherType    = cipherType;
                        aTest.ecDigestType  = ecDigestType;
                        aTest.testType      = TTECSignatureGeneration;
                        aTest.msg           = msg;

                        // Clear repeat values for next round of data gathering
                        msg                 = nil;
                    }
                }
                    break;

                case TTECSignatureGenerationComponent:          // EC Signature Generation Component
                {   // Ensure we have all parameters
                    if (nil != curve && nil != msg)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.curve         = curve;
                        aTest.cipherType    = cipherType;
                        aTest.ecDigestType  = ecDigestType;
                        aTest.testType      = TTECSignatureGenerationComponent;
                        aTest.msg           = msg;

                        // Clear repeat values for next round of data gathering
                        msg                 = nil;
                    }
                }
                    break;

                case TTECSignatureVerification:                 // EC Signature Verification
                {   // Ensure we have all parameters
                    if (nil != curve    && nil != msg          && nil != qX    &&
                        nil != qY       && nil != capitalRData && nil != sData  )
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.curve         = curve;
                        aTest.cipherType    = cipherType;
                        aTest.ecDigestType  = ecDigestType;
                        aTest.testType      = TTECSignatureVerification;
                        aTest.msg           = msg;
                        aTest.qX            = qX;
                        aTest.qY            = qY;
                        aTest.capitalRData  = capitalRData;
                        aTest.sData         = sData;

                        // Clear repeat values for next round of data gathering
                        msg                 = nil;
                        qX                  = nil;
                        qY                  = nil;
                        capitalRData        = nil;
                        sData               = nil;
                    }
                }
                    break;

                case TTECPublicKeyVerification:                 // EC Public Key Verification
                {   // Ensure we have all parameters
                    if (nil != curve    &&
                        nil != qX       &&
                        nil != qY)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.curve         = curve;
                        aTest.qX            = qX;
                        aTest.qY            = qY;
                        aTest.cipherType    = cipherType;
                        aTest.testType      = TTECPublicKeyVerification;

                        // Clear repeat values for next round of data gathering
                        // NOTE: curve is not reset.
                        qX                  = nil;
                        qY                  = nil;
                    }
                }
                    break;

                case TTAESKeyWrap:                              // AES Key Wrapping
                {   // Ensure we have all parameters
                    if (nil != msg &&   nil != ptLength     &&
                        nil != key &&   nil != plainText    )
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.cipherType    = cipherType;
                        aTest.testType      = testType;
                        aTest.msg           = msg;
                        aTest.length        = ptLength;
                        aTest.key           = key;
                        aTest.plainText     = plainText;
                        aTest.encryption    = encryption;

                        // Clear repeat values for next round of data gathering
                        key                 = nil;
                        plainText           = nil;
                    }
                }
                    break;

                case TTAESKeyWrapPad:                           // AES Key Wrapping with Pad
                {   // Ensure we have all parameters
                    if (nil != msg &&   nil != ptLength     &&
                        nil != key &&   nil != plainText    )
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.cipherType    = cipherType;
                        aTest.testType      = testType;
                        aTest.msg           = msg;
                        aTest.length        = ptLength;
                        aTest.key           = key;
                        aTest.plainText     = plainText;
                        aTest.encryption    = encryption;

                        // Clear repeat values for next round of data gathering
                        key                 = nil;
                        plainText           = nil;
                    }

                }                                           //  -- Not Currently implemented in CoreCrypto
                    break;

                case TTECDHPrimFuncOnePassDH:                   // ECDH Primitive Function - One Pass DH
                {   // Determine if this is for "Initiator" or "Responder" Role
                    if ([fileName  isEqual: @"KASFunctionTest_ECCOnePassDH_NOKC_ZZOnly_resp.req"])  // Responder Role
                    {   // Ensure we have all parameters
                        if (nil != QeX &&
                            nil != QeY &&
                            nil != curve    )
                        {
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType    = cipherType;
                            aTest.testType      = testType;
                            aTest.ecDigestType  = ecDigestType;
                            aTest.curve         = curve;
                            aTest.QeX           = QeX;
                            aTest.QeY           = QeY;

                            // Clear repeat values for next round of data gathering
                            QeX             = nil;
                            QeY             = nil;
                        }
                    }
                    else    // Initiator Role
                    {   // Ensure we have all parameters
                        if (nil != QsX &&
                            nil != QsY &&   nil != curve)
                        {
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType    = cipherType;
                            aTest.testType      = testType;
                            aTest.ecDigestType  = ecDigestType;
                            aTest.curve         = curve;
                            aTest.QsX           = QsX;
                            aTest.QsY           = QsY;

                            // Clear repeat values for next round of data gathering
                            QsX                 = nil;
                            QsY                 = nil;
                        }
                    }
                }
                    break;

                case TTECDHPrimValOnePassDH:                    // ECDH Primitive Validity - One Pass DH
                {   // Determine if this is for "Initiator" or "Responder" Role
                    if ([fileName  isEqual: @"KASValidityTest_ECCOnePassDH_NOKC_ZZOnly_resp.req"])  // Responder Role
                    {   // Ensure we have all parameters
                        if (nil != QeX &&   nil != dsIUT  &&
                            nil != QeY &&   nil != QsIUTx &&
                            nil != QsIUTy &&    nil != HashZZ)
                        {
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType    = cipherType;
                            aTest.testType      = testType;
                            aTest.ecDigestType  = ecDigestType;
                            aTest.curve         = curve;
                            aTest.QeX           = QeX;
                            aTest.QeY           = QeY;
                            aTest.dsIUT         = dsIUT;
                            aTest.QsIUTx        = QsIUTx;
                            aTest.QsIUTy        = QsIUTy;
                            aTest.HashZZ        = HashZZ;

                            // Clear repeat values for next round of data gathering
                            QeX                 = nil;
                            QeY                 = nil;
                            dsIUT               = nil;
                            QsIUTx              = nil;
                            QsIUTy              = nil;
                            HashZZ              = nil;
                        }
                    }
                    else    // Initiator Role
                    {   // Ensure we have all parameters
                        if (nil != QsX &&   nil != deIUT  &&
                            nil != QsY &&   nil != QeIUTx &&
                            nil != QeIUTy &&    nil != HashZZ)
                        {
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType    = cipherType;
                            aTest.testType      = testType;
                            aTest.ecDigestType  = ecDigestType;
                            aTest.curve         = curve;
                            aTest.QsX           = QsX;
                            aTest.QsY           = QsY;
                            aTest.deIUT         = deIUT;
                            aTest.QeIUTx        = QeIUTx;
                            aTest.QeIUTy        = QeIUTy;
                            aTest.HashZZ        = HashZZ;

                            // Clear repeat values for next round of data gathering
                            QsX                 = nil;
                            QsY                 = nil;
                            deIUT               = nil;
                            QeIUTx              = nil;
                            QeIUTy              = nil;
                            HashZZ              = nil;
                        }
                    }
                }
                    break;

                case TTECDHPrimFuncEphemeralUnified:            // ECDH Primitive Function - Ephemeral Unified
                    break;                                      //  -- Not Currently implemented in CoreCrypto

                case TTECDHPrimFuncOnePassDH_KDFConcat:         // ECDH Primitive Function - One Pass DH w/KDF Concatenation
                                                                //  -- Not Currently implemented in CoreCrypto
                {   // Determine if this is for "Initiator" or "Responder" Role
                    if ([fileName  isEqual: @"KASFunctionTest_ECCOnePassDH_KDFConcat_NOKC_resp.req"]) // Responder Role
                    {   // Ensure we have all parameters
                        if (nil != QeX   &&     nil != curve &&
                            nil != QeY   &&     nil != nonce)
                        {
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType    = cipherType;
                            aTest.testType      = testType;
                            aTest.ecDigestType  = ecDigestType;
                            aTest.curve         = curve;
                            aTest.QeX           = QeX;
                            aTest.QeY           = QeY;
                            aTest.nonce         = nonce;

                            // Clear repeat values for next round of data gathering
                            QeX                 = nil;
                            QeY                 = nil;
                            nonce               = nil;
                        }
                    }
                    else    // Initiator Role
                    {   // Ensure we have all parameters
                        if (nil != QsX   &&     nil != curve &&
                            nil != QsY   &&     nil != nonce )
                        {
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType    = cipherType;
                            aTest.testType      = testType;
                            aTest.ecDigestType  = ecDigestType;
                            aTest.curve         = curve;
                            aTest.QsX           = QsX;
                            aTest.QsY           = QsY;
                            aTest.nonce         = nonce;

                            // Clear repeat values for next round of data gathering
                            QsX                 = nil;
                            QsY                 = nil;
                            nonce               = nil;
                        }
                    }
                }
                    break;

                case TTECDHPrimFuncStaticUnified:               // ECDH Primitive Function - Static Unified
                                                                //  -- Not Currently implemented in CoreCrypto
                {   // Ensure we have all parameters
                    if (nil != QsX &&
                        nil != QsY &&   nil != curve)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.cipherType    = cipherType;
                        aTest.testType      = testType;
                        aTest.ecDigestType  = ecDigestType;
                        aTest.curve         = curve;
                        aTest.QsX           = QsX;
                        aTest.QsY           = QsY;

                        // Clear repeat values for next round of data gathering
                        QsX                 = nil;
                        QsY                 = nil;
                    }
                }
                    break;

                case TTECDHPrimFuncFullUnified:                 // ECDH Primitive Function - Full Unified
                    break;                                      //  -- Not Currently implemented in CoreCrypto

                case TTECDHPrimFuncOnePassUnified:              // ECDH Primitive Function - One Pass Unified
                                                                //  -- Not Currently implemented in CoreCrypto
                {   // Ensure we have all parameters
                    if (nil != QeX &&   nil != QsX &&
                        nil != QeY &&   nil != QsY &&   nil != curve)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.cipherType    = cipherType;
                        aTest.testType      = testType;
                        aTest.ecDigestType  = ecDigestType;
                        aTest.curve         = curve;
                        aTest.QeX           = QeX;
                        aTest.QeY           = QeY;
                        aTest.QsX           = QsX;
                        aTest.QsY           = QsY;

                        // Clear repeat values for next round of data gathering
                        QeX                 = nil;
                        QeY                 = nil;
                        QsX                 = nil;
                        QsY                 = nil;
                    }
                }
                    break;

                case TTECDHPrimValEphemeralUnified:             // ECDH Primitive Validity - Ephemeral Unified
                                                                //  -- Not Currently implemented in CoreCrypto
                {   // Ensure we have all parameters
                    if (nil != QeX    &&   nil != deIUT  &&
                        nil != QeY    &&   nil != QeIUTx &&
                        nil != HashZZ &&   nil != QeIUTy &&    nil != curve)
                    {

                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.cipherType    = cipherType;
                        aTest.testType      = testType;
                        aTest.ecDigestType  = ecDigestType;
                        aTest.curve         = curve;
                        aTest.QeX           = QeX;
                        aTest.QeY           = QeY;
                        aTest.deIUT         = deIUT;
                        aTest.QeIUTx        = QeIUTx;
                        aTest.QeIUTy        = QeIUTy;
                        aTest.HashZZ        = HashZZ;

                        // Clear repeat values for next round of data gathering
                        QeX                 = nil;
                        QeY                 = nil;
                        deIUT               = nil;
                        QeIUTx              = nil;
                        QeIUTy              = nil;
                        HashZZ              = nil;
                    }
                }
                    break;

                case TTECDHPrimValFullUnified:                  // ECDH Primitive Validity - Full Unified
                                                                //  -- Not Currently implemented in CoreCrypto
                {   // Ensure we have all parameters
                    if (nil != QeX &&   nil != QsY &&   nil != deIUT  &&    nil != dsIUT &&
                        nil != QeY &&   nil != QsX &&   nil != QeIUTx &&    nil != QsIUTx &&
                                                        nil != QeIUTy &&    nil != QsIUTy &&    nil != HashZZ)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.cipherType    = cipherType;
                        aTest.testType      = testType;
                        aTest.ecDigestType  = ecDigestType;
                        aTest.curve         = curve;
                        aTest.QeX           = QeX;
                        aTest.QeY           = QeY;
                        aTest.QsX           = QsX;
                        aTest.QsY           = QsY;
                        aTest.deIUT         = deIUT;
                        aTest.QeIUTx        = QeIUTx;
                        aTest.QeIUTy        = QeIUTy;
                        aTest.dsIUT         = dsIUT;
                        aTest.QsIUTx        = QsIUTx;
                        aTest.QsIUTy        = QsIUTy;
                        aTest.HashZZ        = HashZZ;

                        // Clear repeat values for next round of data gathering
                        QeX                 = nil;
                        QeY                 = nil;
                        QsX                 = nil;
                        QsY                 = nil;
                        deIUT               = nil;
                        QeIUTx              = nil;
                        QeIUTy              = nil;
                        dsIUT               = nil;
                        QsIUTx              = nil;
                        QsIUTy              = nil;
                        HashZZ              = nil;
                    }
                }
                    break;

                case TTECDHPrimValOnePassDH_KDFConcat:          // ECDH Primitive Validity - One Pass DH w/KDF Concatenation
                                                                //  -- Not Currently implemented in CoreCrypto
                {   // Determine if this is for "Initiator" or "Responder" Role
                    if ([fileName  isEqual: @"KASValidityTest_ECCOnePassDH_KDFConcat_NOKC_resp.req"])   // Responder Role
                    {   // Ensure we have all parameters
                        if (nil != QeX    &&    nil != dsIUT  &&    nil != nonce  &&
                            nil != QeY    &&    nil != QsIUTx &&    nil != OI     &&
                                                nil != QsIUTy &&    nil != CAVSTag )
                        {
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType    = cipherType;
                            aTest.testType      = testType;
                            aTest.ecDigestType  = ecDigestType;
                            aTest.curve         = curve;
                            aTest.QeX           = QeX;
                            aTest.QeY           = QeY;
                            aTest.dsIUT         = dsIUT;
                            aTest.QsIUTx        = QsIUTx;
                            aTest.QsIUTy        = QsIUTy;
                            aTest.nonce         = nonce;
                            aTest.OI            = OI;
                            aTest.CAVSTag       = CAVSTag;

                            // Clear repeat values for next round of data gathering
                            QeX                 = nil;
                            QeY                 = nil;
                            dsIUT               = nil;
                            QsIUTx              = nil;
                            QsIUTy              = nil;
                            nonce               = nil;
                            OI                  = nil;
                            CAVSTag             = nil;
                        }
                    }
                    else    // Initiator Role
                    {   // Ensure we have all parameters
                        if (nil != QsX    &&    nil != deIUT  &&    nil != nonce  &&
                            nil != QsY    &&    nil != QeIUTx &&    nil != OI     &&
                                                nil != QeIUTy &&    nil != CAVSTag )
                        {
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType    = cipherType;
                            aTest.testType      = testType;
                            aTest.ecDigestType  = ecDigestType;
                            aTest.curve         = curve;
                            aTest.QsX           = QsX;
                            aTest.QsY           = QsY;
                            aTest.deIUT         = deIUT;
                            aTest.QeIUTx        = QeIUTx;
                            aTest.QeIUTy        = QeIUTy;
                            aTest.nonce         = nonce;
                            aTest.OI            = OI;
                            aTest.CAVSTag       = CAVSTag;

                            // Clear repeat values for next round of data gathering
                            QsX                 = nil;
                            QsY                 = nil;
                            deIUT               = nil;
                            QeIUTx              = nil;
                            QeIUTy              = nil;
                            nonce               = nil;
                            OI                  = nil;
                            CAVSTag             = nil;
                        }
                    }
                }
                    break;

                case TTECDHPrimValOnePassUnified:               // ECDH Primitive Validity - One Pass Unified
                                                                //  -- Not Currently implemented in CoreCrypto
                {   // Determine if this is for "Initiator" or "Responder" Role
                    if ([fileName  isEqual: @"KASValidityTest_ECCOnePassUnified_NOKC_ZZOnly_resp.req"])
                    {   // Ensure we have all parameters
                        if (nil != QsX &&   nil != QeX &&   nil != dsIUT  &&
                            nil != QsY &&   nil != QeY &&   nil != QsIUTx &&
                                                            nil != QsIUTy &&    nil != HashZZ)
                        {
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType    = cipherType;
                            aTest.testType      = testType;
                            aTest.ecDigestType  = ecDigestType;
                            aTest.curve         = curve;
                            aTest.QsX           = QsX;
                            aTest.QsY           = QsY;
                            aTest.QeX           = QeX;
                            aTest.QeY           = QeY;
                            aTest.dsIUT         = dsIUT;
                            aTest.QsIUTx        = QsIUTx;
                            aTest.QsIUTy        = QsIUTy;
                            aTest.HashZZ        = HashZZ;

                            // Clear repeat values for next round of data gathering
                            QsX                 = nil;
                            QsY                 = nil;
                            QeX                 = nil;
                            QeY                 = nil;
                            dsIUT               = nil;
                            QsIUTx              = nil;
                            QsIUTy              = nil;
                            HashZZ              = nil;
                        }
                    }
                    else    // Initiator Role
                    {   // Ensure we have all parameters
                        if (nil != QsX &&   nil != dsIUT  &&    nil != deIUT  &&
                            nil != QsY &&   nil != QsIUTx &&    nil != QeIUTx &&
                                            nil != QsIUTy &&    nil != QeIUTy &&    nil != HashZZ)
                        {
                            aTest = [[[TestFileData alloc] init] autorelease];
                            aTest.cipherType = cipherType;
                            aTest.testType = testType;
                            aTest.ecDigestType = ecDigestType;
                            aTest.curve = curve;

                            aTest.QsX = QsX;
                            aTest.QsY = QsY;
                            aTest.dsIUT = dsIUT;
                            aTest.QsIUTx = QsIUTx;
                            aTest.QsIUTy = QsIUTy;
                            aTest.deIUT = deIUT;
                            aTest.QeIUTx = QeIUTx;
                            aTest.QeIUTy = QeIUTy;
                            aTest.HashZZ = HashZZ;

                            // Clear repeat values for next round of data gathering
                            QsX = nil;
                            QsY = nil;
                            dsIUT = nil;
                            QsIUTx = nil;
                            QsIUTy = nil;
                            deIUT = nil;
                            QeIUTx = nil;
                            QeIUTy = nil;
                            HashZZ = nil;
                        }
                    }
                }
                    break;

                case TTECDHPrimValStaticUnified:                // ECDH Primitive Validity - Static Unified
                                                                //  -- Not Currently implemented in CoreCrypto
                {
                    if (nil != QsX &&   nil != dsIUT  &&
                        nil != QsY &&   nil != QsIUTx &&
                                        nil != QsIUTy &&    nil != HashZZ)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.cipherType    = cipherType;
                        aTest.testType      = testType;
                        aTest.ecDigestType  = ecDigestType;
                        aTest.curve         = curve;
                        aTest.QsX           = QsX;
                        aTest.QsY           = QsY;
                        aTest.dsIUT         = dsIUT;
                        aTest.QsIUTx        = QsIUTx;
                        aTest.QsIUTy        = QsIUTy;
                        aTest.HashZZ        = HashZZ;

                        // Clear repeat values for next round of data gathering
                        QsX                 = nil;
                        QsY                 = nil;
                        dsIUT               = nil;
                        QsIUTx              = nil;
                        QsIUTy              = nil;
                        HashZZ              = nil;
                    }
                }
                    break;

                case TTECDHCurve25519GenerateShared:            // ECDH-Curve25519 Generate Test
                                                                // APPLE_SEP
                {
                    if (nil != classBStaticPrivKey &&
                        nil != classBStaticPubKey)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType              = testType;
                        aTest.ecDigestType          = ecDigestType;
                        aTest.cipherType            = cipherType;
                        aTest.classBStaticPrivKey   = classBStaticPrivKey;
                        aTest.classBStaticPubKey    = classBStaticPubKey;

                        // Clear repeat values for next round of data gathering
                        classBStaticPrivKey         = nil;
                        classBStaticPubKey          = nil;
                    }
                }
                    break;

                case TTECDHCurve25519VerifyShared:              // ECDH-Curve25519 Verify Test
                                                                // APPLE_SEP
                {
                    if (nil != classBStaticPrivKey  &&
                        nil != classBStaticPubKey   &&
                        nil != classBEphemPrivKey   &&
                        nil != classBEphemPubKey    &&
                        nil != classBSharedSecret   )
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType              = testType;
                        aTest.ecDigestType          = ecDigestType;
                        aTest.cipherType            = cipherType;
                        aTest.classBStaticPrivKey   = classBStaticPrivKey;
                        aTest.classBStaticPubKey    = classBStaticPubKey;
                        aTest.classBEphemPrivKey    = classBEphemPrivKey;
                        aTest.classBEphemPubKey     = classBEphemPubKey;
                        aTest.classBSharedSecret    = classBSharedSecret;

                        // Clear repeat values for next round of data gathering
                        classBStaticPrivKey         = nil;
                        classBStaticPubKey          = nil;
                        classBEphemPrivKey          = nil;
                        classBEphemPubKey           = nil;
                        classBSharedSecret          = nil;
                    }
                }
                    break;

                case TTECDHCurve25519KeyVerify:                 // ECDH-Curve25519 Key Verify Test
                                                                // APPLE_SEP
                {
                    if (nil != classBStaticPrivKey  &&
                        nil != classBStaticPubKey)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType              = testType;
                        aTest.ecDigestType          = ecDigestType;
                        aTest.cipherType            = cipherType;
                        aTest.classBStaticPrivKey   = classBStaticPrivKey;
                        aTest.classBStaticPubKey    = classBStaticPubKey;

                        // Clear repeat values for next round of data gathering
                        classBStaticPrivKey         = nil;
                        classBStaticPubKey          = nil;
                    }
                }
                    break;

                case TTECDHCurve25519KeyGenerate:               // ECDH-Curve25519 Key Generation Test
                                                                // APPLE_SEP
                {
                    if (nil != numKeysValue)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType              = testType;
                        aTest.ecDigestType          = ecDigestType;
                        aTest.cipherType            = cipherType;
                        aTest.numKeys               = numKeysValue;

                        // Clear repeat values for next round of data gathering
                        numKeysValue                = nil;
                    }
                }
                    break;

                case TTFIPSPOST:
                {
                    if (0 != fipsMode)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType = testType;
                        aTest.nValue = [NSNumber numberWithInteger:fipsMode];
                        fipsMode = 0;
                    }
                }
                    break;

                case TTHKDF:
                {
                    if (cipherType != TFCipherUnknown && ikm != nil &&
                            salt != nil && info != nil && okmLength != nil)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType = testType;
                        aTest.key = ikm;
                        aTest.nonce = salt;
                        aTest.tag = info;
                        aTest.length = okmLength;
                        aTest.cipherType = cipherType;

                        okmLength = nil;
                        ikm = salt = info = nil;
                    }
                }
                    break;

                case TTFFDHKeyGenerate:
                {
                    if (nil != numKeysValue)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType = testType;
                        aTest.nValue = numKeysValue;
                        numKeysValue = nil;
                    }
                }
                    break;

                case TTFFDHFunction:
                {
                    if (nil != capitalPData && nil != capitalQData && nil != capitalGData && nil != capitalYData)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType = testType;
                        aTest.capitalPData = capitalPData;
                        aTest.capitalQData = capitalQData;
                        aTest.capitalGData = capitalGData;
                        aTest.capitalYData = capitalYData;
                        capitalYData = nil;
                    }
                }
                    break;

                case TTFFDHValidity:
                {
                    if (nil != capitalPData && nil != capitalQData && nil != capitalGData &&
                            nil != capitalYData && nil != xp1 && nil != xp2 && nil != msg)
                    {
                        aTest = [[[TestFileData alloc] init] autorelease];
                        aTest.testType = testType;
                        aTest.capitalPData = capitalPData;
                        aTest.capitalQData = capitalQData;
                        aTest.capitalGData = capitalGData;
                        aTest.capitalYData = capitalYData;
                        aTest.xp1 = xp1;                // XephemIUT
                        aTest.xp2 = xp2;                // YephemIUT
                        aTest.msg = msg;                // CAVSHashZZ
                        capitalYData = xp1 = xp2 = msg = nil;
                    }
                }
                    break;

                default:                                        // Unknown or unsupported Test Type
                {
                    fprintf(stderr, "Undefined Test Case\n");
                    [pool drain];
                    return result;
                }
            }



            // ---------------------------------------------------------------------------------
            //
            // If we actual have a test case, retain it for subsequent processing
            //
            if (nil != aTest)   // Valid Test Case
            {
                aTest.fileName      = fileName;
                aTest.keyString     = self.keyString;
                aTest.testTarget    = self.testTarget;

                [tempTestItems addObject:aTest];    // Add Test Items to tempTestItems array
                aTest               = nil;          // Reset Test Items array
            }
        }

        //
        // Everything has been parsed for this request (.req) file
        // Set the current set of test Environment variables into the Test Group Dictionary
        [tempTestGroupDictionary setObject:tempTestEnvironItems forKey:TFEnvironmentDataKey];

        // Set the current set of tests seen before getting this environment variable.
        [tempTestGroupDictionary setObject:tempTestItems forKey:TFTestKey];

        // Add the existing Test Group Dictionary to the array of test groups
        [tempTestGroupArray addObject:tempTestGroupDictionary];

        [tempFileDictionary setObject:fileHeaderStrings forKey:TFFileHeaderKey];
        [tempFileDictionary setObject:tempTestGroupArray forKey:TFTestGroupKey];
        [tempFileDictionary setObject:[NSNumber numberWithBool:groupCountReset] forKey:TFGroupCountReset];

        result = [[NSDictionary dictionaryWithDictionary:tempFileDictionary] retain];

        groupCountReset = YES;

        // Log Test File Parsing Complete
        if (dispatcher.verbose) printf("[TestFileParser][parseLines] Completed file  [%s]\n", [fileName UTF8String]);
    }
    [pool drain];
    return result;
}


/* ----------------------------------------------------------------------------------------
    Method:         parse
    Description:    This method does the work of parsing a Request (.req) file and creating
                    the TestFileData object.
 ---------------------------------------------------------------------------------------- */
- (NSDictionary*)parse
{
    NSAutoreleasePool* pool = [NSAutoreleasePool new];
    NSDictionary*    result = nil;

    NSFileManager* fManager = [NSFileManager defaultManager];
    BOOL        isDirectory = NO;

    // First, ensure that the passed in path exists and is a directory
    if (nil == _parseDirectory ||
        ![fManager fileExistsAtPath:_parseDirectory isDirectory:&isDirectory] ||
        !isDirectory)
    {
        fprintf(stderr, "The directory provided [%s] is invalid\n", [_parseDirectory UTF8String]);
        [pool drain];
        return result;
    }

    //
    // Enumerate the directory to ensure we are only procesing Request (.req) Files
    //
    NSError* error      = nil;
    NSDirectoryEnumerator* dirEnumerator = [fManager enumeratorAtPath:_parseDirectory];
    NSString* fileName  = nil;

    while (nil != (fileName = [dirEnumerator nextObject]))
    {
        StackPool innerPool;

        // First, make sure this is a "dot" file
        if ([fileName hasPrefix:@"."])  continue;

        // Make sure this is a request (.req) file
        if (![@"req" isEqualToString:[fileName pathExtension]])
        {
            fprintf(stderr,"[%s] is not a request (.req) file\n", [fileName UTF8String]);
            continue;
        }

        NSString* filePath = [_parseDirectory stringByAppendingPathComponent:fileName];
        NSData*   fileData = [NSData dataWithContentsOfFile:filePath options:0 error:&error];
        if (nil != error || nil == fileData)
        {
            fprintf(stderr, "Unable to read the file [%s]\n", [filePath UTF8String]);
            continue;
        }

        // This parser *ASSUMES* that the data is a text file.  To make things easier,
        // convert the data into a giant string which we will parse line by line
        NSString* strData = [[[NSString alloc] initWithData:fileData encoding:NSUTF8StringEncoding] autorelease];
        if (nil == strData)
        {
            fprintf(stderr, "Unable to convert the file data for [%s] into text data\n", [filePath UTF8String]);
            continue;
        }

        // Put each line from the file into a single string for further parsing
        NSArray*            lineArray  = [strData componentsSeparatedByString:@"\n"];
        CAVSTestDispatcher* dispatcher = [CAVSTestDispatcher currentTestDispatcher];

        if (dispatcher.verbose) // Log Start of Test File Parsing
        {
            printf("Begin parsing file:      [%s]\n", [fileName UTF8String]);
            printf("=================================================================================\n");
        }

        // Parse all lines found in the test file
        NSDictionary* fileDictionary = [self parseLines:lineArray fileName:fileName];

        if (dispatcher.verbose) // Log End of Test File Parsing
        {
            printf("=================================================================================\n");
            printf("Completed parsing file:  [%s]\n\n", [fileName UTF8String]);
        }
        if (fileDictionary == nil)
        {
            printf("Failed to successfuly parse file [%s], discarding.\n", [fileName UTF8String]);
            return nil;
        }

        [_parseTree setObject:fileDictionary forKey:fileName];
        [fileDictionary release];
    }

    [pool drain];
    result = [NSDictionary dictionaryWithDictionary:_parseTree];
    return result;
}

@end
