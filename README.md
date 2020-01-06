/*
* Copyright (c) 2010,2012,2016,2017,2018 Apple Inc. All rights reserved.
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

The corecrypto (cc) project
===========================

The main goal is to provide low level fast math routines and crypto APIs which
can be used in various environments (Kernel, bootloader, userspace, etc.).  It
is an explicit goal to minimize dependancies between modules and functions so
that clients of this library only end up with the routines they need and
nothing more.

Corecrypto compiles under all Apple OSs, Windows and Linux.

Corecrypto Modules
------------------

Current corecrypto consists of the following submodules:

* `cc`:			  Headers and code common to all of the modules
* `ccasn1`:		  ASN.1 typeid constants and ccoid definition.
* `ccder`:		  DER encoding decoding support
* `ccn`:		  Math on vectors of n cc_units
* `cczp`:		  Modular arithmetic mod integer p, on vectors of n cc_units
* `ccz`:          Variable sized signed integer math routines
* `ccdrbg`:       Deterministic Random Byte Generators
* `ccrng`:        Random Bytes Generators
* `ccdh`:         Diffie-Hellman routines.
* `ccec25519`:    Elliptic curve signature and Diffie-Hellman routines using the Edward's 25519 curve
* `ccrsa`:        RSA routines.
* `ccec`:         Eliptic Curve Curves, ec specific math and APIs
* `ccdigest`:     Digest abstraction layer.
* `cchmac`:       HMAC using any ccdigest.
* `ccpbkdf2`:     PKKDF2 using any ccdigest.
* `ccmd2`:        MD2 digest implementations.
* `ccmd4`:        MD4 digest implementations.
* `ccmd5`:        MD5 digest implementations.
* `ccripemd`:     RIPE-MD digest implementations.
* `ccsha1`:       SHA-1 digest implementations.
* `ccsha2`:       SHA-2 digest implementations.
* `ccmode`:       Symmetric cipher chaining mode interfaces.
* `ccpad`:        Symmetric cipher padding code.
* `ccaes`:        AES symmetric cipher implementations.
* `ccblowfish`:   Blowfish symmetric cipher implementations.
* `cccast`:       Cast symmetric cipher implementations.
* `ccdes`:        DES and 3DES symmetric cipher implementations.
* `ccrc2`:        RC2 symmetric cipher implementations.
* `ccrc4`:        RC4 symmetric cipher implementations.
* `ccperf`:       Performance testing harness.
* `cctest`:       Common utilities for creating self tests and XCunit tests.
* `ccprime`:      Functions for generating large prime numbers. Mostly used in RSA key generation.

### Module Subdirectories

Each module has the following subdirectories:

* `corecrypto`:     headers for this module
* `src`:            sources for this module
* `doc`:            documentation, references, etc.
* `xcunit`:         XCTest based unit tests for this module.
* `crypto_tests`:   sources for executable tests for this module
* `test_vectors`:   test vectors for this module
* `tools`:          sources for random helper tools.

The following subdirections don't follow the module layout yet:

* `corecrypto_kext`:   Supporting files for kernel extension build and fips support.
* `corecrypto_dylib`:  Supporting files for userspace shared lib build and fips support.

ARMV6m
------
The ARMV6m is not on corecrypto project target list. To compile corecrypto under ARMV6m use the following command:
`$xcodebuild -target "corecrypto_static" OTHER_CFLAGS="-Qunused-arguments" -sdk iphoneos.internal -arch armv6m`


Windows
-------
corecrypto compiles under Windows using Visual Studio 2015 and Clang with Microsoft CodeGen. The corecrypto Solution contains three projects:

1. `corecrypto`: This projects compiles corecrypto, and produces a static library in 32 and 64 bit modes.
2. `corecrypto_test`: This project compiles corecrypto test files and links statically with the corecrypto debug library.
3. `corecrypto_perf`: This project compiles corecrypto performance measurement files and links statically with the corecrypto release library.
4. `corecrypto_wintest`: This project contains a simple code that links to the corecrypto.lib and complies in c++ using the Visul C++ compiler. This project created to
   make sure corecrypto library can linked to c++ software that are compiled with the Microsoft Compiler.

Linux
-----
corecrypto library, `corecrypto_test` and  `corecrypto_perf` complie under Linux. The Linux make file is not uptodate. 

Prototypes changes:
-------------------
From time to time, corecrypto needs to change the prototypes of functions.
In this case, we use a macro defined as:
CC_CHANGEFUNCTION_<radar>_<function name>
and the header will document instructions to migrate from the old to new function prototype.



