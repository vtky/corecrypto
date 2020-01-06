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

#ifndef ccrng_cryptographic_priv_h
#define ccrng_cryptographic_priv_h

#if defined (_WIN32)
#include <windows.h>
#endif

//==============================================================================
//
//          ccrng support for multithreaded environments
//
// This part of corecrypto is OS dependent and it serves two purposes
// a) It allows multiple threads to use ccrng()
// b) If the process is forked, it reseeds the ccrng, so that parent and child
//    state differs and generate different random numbers
//==============================================================================

//#if CC_LINUX && CC_KERNEL && CC_XNU_KERNEL_AVAILABLE && CORECRYPTO_SIMULATE_POSIX_ENVIRONMENT
//  #define CC_RNG_MULTITHREAD_POSIX    0 //this is only to allow linux development on macOS. It is not useful in practice.
//  #define CC_RNG_MULTITHREAD_DISPATCH 0
//  #define CC_RNG_MULTITHREAD_WIN      0
//  #define CC_RNG_MULTITHREAD_KERNEL   1
//#elif CC_LINUX || CORECRYPTO_PUBLIC_SDK //for systems that support pthread, such as Linux
//  #define CC_RNG_MULTITHREAD_POSIX    1
//  #define CC_RNG_MULTITHREAD_DISPATCH 0
//  #define CC_RNG_MULTITHREAD_WIN      0
//  #define CC_RNG_MULTITHREAD_KERNEL   0
//#elif CC_XNU_KERNEL_AVAILABLE && !CC_KERNEL && !CC_USE_L4 && !CC_EFI //For Apple OSs (macOS, iOS, watchOS, tvOS), except kernel, L4 and EFI
// #define CC_RNG_MULTITHREAD_POSIX    0
// #define CC_RNG_MULTITHREAD_DISPATCH 1
// #define CC_RNG_MULTITHREAD_WIN      0
// #define CC_RNG_MULTITHREAD_KERNEL   0
//#elif CC_XNU_KERNEL_AVAILABLE && CC_KERNEL //For the Apple Kernel
// #define CC_RNG_MULTITHREAD_POSIX    0
// #define CC_RNG_MULTITHREAD_DISPATCH 0
// #define CC_RNG_MULTITHREAD_WIN      0
// #define CC_RNG_MULTITHREAD_KERNEL   1
//#elif defined(_WIN32) //for Windows
 #define CC_RNG_MULTITHREAD_POSIX    0
 #define CC_RNG_MULTITHREAD_DISPATCH 0
 #define CC_RNG_MULTITHREAD_WIN      1
 #define CC_RNG_MULTITHREAD_KERNEL   0
//#else
// #error No multithread environment defined for ccrng_cryptographic.
//#endif

//------------------------------------------------------------------------------
//          Dispatch library, iOS/OSX
//------------------------------------------------------------------------------
#if CC_RNG_MULTITHREAD_DISPATCH
#include <pthread.h>
#include <dispatch/dispatch.h>
#include <dispatch/private.h>

#define CC_INIT_ONCE(_function_)   static dispatch_once_t _init_controller_; \
dispatch_once(&_init_controller_, ^{_function_();})

#ifndef __BLOCKS__
#warning no blocks support
#endif /* __BLOCKS__ */

#define VAR_IN_LOCK      __block
#define LOCK(rng)             dispatch_sync((rng)->crypto_rng_q,^{
#define UNLOCK(rng)           });


//------------------------------------------------------------------------------
//          POSIX library, Linux
//------------------------------------------------------------------------------
#elif CC_RNG_MULTITHREAD_POSIX 
#include <pthread.h>

#define CC_INIT_ONCE(_function_)   \
static pthread_once_t _init_controller_=PTHREAD_ONCE_INIT; \
pthread_once(&_init_controller_, (void (*)(void))_function_)

#define VAR_IN_LOCK
#define LOCK(rng)					  while (pthread_mutex_trylock(&((rng)->mutex)) != 0);
#define UNLOCK(rng)                   pthread_mutex_unlock(&((rng)->mutex))


//------------------------------------------------------------------------------
//          Kext, XNU
//------------------------------------------------------------------------------
#elif CC_RNG_MULTITHREAD_KERNEL

#include <kern/locks.h>
#define VAR_IN_LOCK
#define LOCK(rng)            lck_mtx_lock((rng)->crypto_rng_q)
#define UNLOCK(rng)          lck_mtx_unlock((rng)->crypto_rng_q)

//------------------------------------------------------------------------------
//          Windows
//------------------------------------------------------------------------------
#elif CC_RNG_MULTITHREAD_WIN 

// _function_ is appended the suffix _win
#define CC_INIT_ONCE(_function_) \
static INIT_ONCE _init_controller_ = INIT_ONCE_STATIC_INIT; \
InitOnceExecuteOnce(&_init_controller_, _function_##_win, NULL, NULL)

#define VAR_IN_LOCK
#define LOCK(rng)         if (WaitForSingleObject((rng)->hMutex, INFINITE) != WAIT_OBJECT_0) return CCERR_INTERNAL;
#define UNLOCK(rng)       ReleaseMutex((rng)->hMutex)

//------------------------------------------------------------------------------
//          default
//------------------------------------------------------------------------------
#else
#error CC_INIT_ONCE(), VAR_IN_LOCK, LOCK() and UNLOCK() are not implemented."
#endif /* CC_RNG_MULTITHREAD_DISPATCH */


#endif /* ccrng_cryptographic_priv_h */
