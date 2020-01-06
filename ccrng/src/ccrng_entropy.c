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

#include <corecrypto/cc_config.h>
#include <corecrypto/ccrng_priv.h>
#include <corecrypto/cc.h>
#include "cc_debug.h"

// This file defines cc_get_entropy() for four environments:
// - OSX/iOS kernel
// - OSX>10.12, iOS>10.0
// - Linux and lower version of OSX/iOS
// - Windows

#if CC_XNU_KERNEL_AVAILABLE
#include <AvailabilityInternal.h>
#endif

#if (!CC_XNU_KERNEL_AVAILABLE \
    || (defined(IPHONE_SIMULATOR_HOST_MIN_VERSION_REQUIRED) && IPHONE_SIMULATOR_HOST_MIN_VERSION_REQUIRED < 100000) \
    ||           ( defined(__MAC_OS_X_VERSION_MIN_REQUIRED) &&            __MAC_OS_X_VERSION_MIN_REQUIRED < 101200) \
    ||           (defined(__IPHONE_OS_VERSION_MIN_REQUIRED) &&           __IPHONE_OS_VERSION_MIN_REQUIRED < 100000) \
    ||           (    defined(__TV_OS_VERSION_MIN_REQUIRED) &&               __TV_OS_VERSION_MIN_REQUIRED < 100000) \
    ||           ( defined(__WATCH_OS_VERSION_MIN_REQUIRED) &&            __WATCH_OS_VERSION_MIN_REQUIRED < 30000))
#define XNU_GET_ENTROPY_SUPPORTED 0
#else
#define XNU_GET_ENTROPY_SUPPORTED 1
#include <sys/random.h>
#endif

//==============================================================================
//
//      KERNEL
//
//==============================================================================

#if CC_KERNEL

#include <sys/types.h>
#include <sys/random.h>
#include <sys/attr.h>

int cc_get_entropy(size_t entropy_size, void *entropy)
{
    if (entropy_size>UINT_MAX) {
        return CCERR_OVERFLOW;
    }
    read_random(entropy, (u_int)entropy_size);
    return 0;
}

#elif XNU_GET_ENTROPY_SUPPORTED

//==============================================================================
//
//      Only getentropy (OSX 10.12 / iOS 10.0), the new syscall "getentropy()
//
//==============================================================================

#define GET_ENTROPY_MAX_PER_REQUEST 256

int cc_get_entropy(size_t entropy_size, void *entropy)
{
    int status = 0;
    // syscall
    while ((status==0) && (entropy_size>GET_ENTROPY_MAX_PER_REQUEST)) {
        /* Can't request more than 256 random bytes
         * at once. Complying with openbsd getentropy()
         */
        status=getentropy(entropy, GET_ENTROPY_MAX_PER_REQUEST);
        entropy_size-=GET_ENTROPY_MAX_PER_REQUEST;
        entropy = (uint8_t*)entropy + GET_ENTROPY_MAX_PER_REQUEST;
    }
    if (status) {return status;}
    return getentropy(entropy, entropy_size);
}

#elif CC_XNU_KERNEL_AVAILABLE || CC_LINUX

//==============================================================================
//
//      dev/random (linux only, OSX<10.12 and iOS<10.0 or for XBS)
//      use getentropy() otherwise
// TODO: consider using getrandom() for Linux
//
//==============================================================================

#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>

#define OP_INTERRUPT_MAX 1024

#if  CC_XNU_KERNEL_AVAILABLE
#define USE_GUARDED_OPEN 1
#include <sys/guarded.h>
#else
#undef USE_GUARDED_OPEN
#endif

#define DEV_RANDOM "/dev/urandom" //on OSX/iOS /dev/urandom is identical to /dev/random

static int init_dev_random(int *pfd)
{
    int status=CCERR_INTERNAL;
    int interrupts = 0;
    *pfd = -1;
    while(*pfd == -1) {
#ifdef USE_GUARDED_OPEN
        guardid_t guard = (uintptr_t)pfd;
        const unsigned int guard_flags = GUARD_CLOSE|GUARD_DUP|GUARD_SOCKET_IPC|GUARD_FILEPORT;
        *pfd = guarded_open_np(DEV_RANDOM, &guard, guard_flags, O_RDONLY | O_CLOEXEC);
#else
        *pfd = open(DEV_RANDOM, O_RDONLY | O_CLOEXEC);
#endif
        if(*pfd != -1) {
            break;
        }
        switch(errno) {
            case EINTR:
                interrupts++;
                if(OP_INTERRUPT_MAX && interrupts > OP_INTERRUPT_MAX) {
                    status=CCERR_INTERUPTS;
                }
                break;
            case EACCES:
                status=CCERR_PERMS;
                break;
            case ENFILE:
            case EMFILE:
                status=CCERR_FILEDESC;
                break;
            case EISDIR:    /* FALLTHROUGH */
            case ELOOP:     /* FALLTHROUGH */
            case ENOENT:    /* FALLTHROUGH */
            case ENXIO:     /* FALLTHROUGH */
            default:
                status=CCERR_CRYPTO_CONFIG;  // We might actually want to abort here - any of these
                                              // indicate a bad entropy.
                break;
        }
    }
    if (*pfd>0) {
        status=0;  // success
    }
    return status;
}

static void close_dev_random(int *pfd) {
#ifdef USE_GUARDED_OPEN
    guardid_t guard = (uintptr_t)pfd;
    guarded_close_np(*pfd, &guard);
#else
    close(*pfd);
#endif
    *pfd=-1;
}

//either gets entropy from getentropy() syscall or opens and closes /dev/urandom on each call
int cc_get_entropy(size_t entropy_size, void *entropy)
{
    int fd;
    int status;

    status=init_dev_random(&fd);

    if(status) return status; // No need to close the file
    int interrupts = 0;
    size_t pos = 0;
    
    while(entropy_size) {
        ssize_t read_now = read(fd, entropy+pos, entropy_size);
        if(read_now > -1) {
            entropy_size -= read_now;
            pos += read_now;
        }
        else if (read_now==0) {
            status=CCERR_OUT_OF_ENTROPY; // End of file is not expected
        }
        else {
            switch(errno) {
                case EINTR:
                    interrupts++;
                    if(OP_INTERRUPT_MAX && interrupts > OP_INTERRUPT_MAX) {
                        status=CCERR_INTERUPTS;
                    }
                    break;
                case EAGAIN:
                    break;
                case EBADF: /* FALLTHROUGH */
                case ENXIO:
                    status=CCERR_DEVICE;
                    break;
                case EACCES:
                    status=CCERR_PERMS;
                    break;
                case EFAULT:
                    status=CCERR_PARAMETER;
                    break;
                case ENOBUFS: /* FALLTHROUGH */
                case ENOMEM:
                    status=CCERR_MEMORY;
                    break;
                default:
                    status=CCERR_CRYPTO_CONFIG;  // TODO We might actually want to abort here - any of these
                    // indicate a bad system.
                    break;
            }//switch
        }//else
        if (status!=0) {break;} // Close fd and return
    }
    close_dev_random(&fd);
    return status;

}
#elif defined(_WIN32)

#include <windows.h>
int cc_get_entropy(size_t entropy_size, void *entropy)
{
	HCRYPTPROV hProvider;

    BOOL rc = CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT | CRYPT_SILENT);
	if (rc == TRUE) {
		rc = CryptGenRandom(hProvider, entropy_size, entropy);
		CryptReleaseContext(hProvider, 0);
    }

	return rc == TRUE ? 0 : CCERR_INTERNAL;
}
#else // getentropy
#error corecrypto requires cc_get_entropy() to be defined.
#endif // !CC_KERNEL

