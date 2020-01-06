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

#ifndef cc_absolute_time_h
#define cc_absolute_time_h

#include <corecrypto/cc_config.h>
#include <stdint.h>

// For more info on mach_absolute_time() precision:
//     https://developer.apple.com/library/mac/qa/qa1398/_index.html

#if CC_USE_L4
    #include <ert/time.h>
    #define cc_absolute_time() ert_time_now()

    // L4 doesn't use a scaling factor
    #define cc_absolute_time_sf() (1.0 / 1000000000.0)
#elif CC_KERNEL
    #include <mach/mach_time.h>
    #include <kern/clock.h>
    #define cc_absolute_time() (mach_absolute_time())

     // Scale factor to convert absolute time to seconds
    #define cc_absolute_time_sf() ({                                        \
        struct mach_timebase_info info;                                     \
        clock_timebase_info(&info);                                         \
        ((double)info.numer) / (1000000000.0 * info.denom);                 \
    })
#elif CC_XNU_KERNEL_AVAILABLE
    #include <mach/mach_time.h>
    #define cc_absolute_time() (mach_absolute_time())

     // Scale factor to convert absolute time to seconds
    #define cc_absolute_time_sf() ({                                        \
        struct mach_timebase_info info;                                     \
        mach_timebase_info(&info);                                          \
        ((double)info.numer) / (1000000000.0 * info.denom);                 \
    })
#elif defined(_WIN32)
    #include <windows.h>
    CC_INLINE uint64_t cc_absolute_time(void) {
        LARGE_INTEGER time;
        QueryPerformanceCounter(&time); //resolution < 1us
        return (uint64_t)time.QuadPart;
     }

     CC_INLINE double cc_absolute_time_sf(){
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq); //performance counter freq in Hz
        return (double)1 / freq.QuadPart;
     }

#elif CC_LINUX
    #if CORECRYPTO_SIMULATE_POSIX_ENVIRONMENT
        #include <mach/mach_time.h>
        #define cc_absolute_time() (mach_absolute_time()) // To test compilation on mac
    #else
        // The following is specific to non x86 (arm/mips/etc...) architectures on Linux.
        #warning cc_absolute_time() has not been tested
        #include <time.h>
        CC_INLINE uint64_t cc_absolute_time() {
           struct timespec tm;
           clock_gettime(CLOCK_THREAD_CPUTIME_ID, &tm);
           return tm.tv_sec * 1000000000ull + tm.tv_nsec;
        }
    #endif // CORECRYPTO_SIMULATE_POSIX_ENVIRONMENT
    #define cc_absolute_time_sf() (1.0 / 1000000000.0)

#else
    #warning Target OS is not defined. There should be a definition for cc_absolute_time() for the target OS/platform.
#endif

#endif /* cc_absolute_time_h */
