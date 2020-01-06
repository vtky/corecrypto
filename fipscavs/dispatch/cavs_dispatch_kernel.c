/*
 * Copyright (c) 2017,2018 Apple Inc. All rights reserved.
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

#include <IOKit/IOKitLib.h>
#include <mach/vm_map.h>

#include "cavs_common.h"
#include "cavs_dispatch_priv.h"
#include "cavs_kext_service.h"

static io_connect_t cavs_dispatch_kernel_setup(const char *serviceName);
static int cavs_dispatch_kernel_op(cavs_vector vector, void *request, size_t request_len,
        uint8_t *result, size_t *result_len);
static io_connect_t cavs_dispatch_kernel_connection = 0;
static io_connect_t cavs_dispatch_kernel_setup(const char *serviceName)
{
    kern_return_t   ret;
    mach_port_t     port;
    io_service_t    service;
    io_iterator_t   iterator;
    io_connect_t    connection = 0;
    CFDictionaryRef match;

    // Get the IOKit master port
    if (IOMasterPort(MACH_PORT_NULL, &port) != KERN_SUCCESS) {
        errorf("IOMasterPort failed");
        return connection;
    }

    // Create a matching dictionary for the driver class
    if ((match = IOServiceNameMatching(serviceName)) == NULL) {
        errorf("IOServiceMatching failed for '%s'", kIOFIPSCipherService);
        return connection;
    }

    // Iterate over the matching instances, consumes dictionary
    if ((IOServiceGetMatchingServices(port, match, &iterator)) != KERN_SUCCESS) {
        errorf("IOServiceGetMatchingServices failed");
        return connection;
    }

    service = IOIteratorNext(iterator);
    if (service == 0) {
        errorf("Class '%s' not found", kIOFIPSCipherService);
        return connection;
    }

    // instantiate the UserClient and release the service object
    ret = IOServiceOpen(service, mach_task_self(), 0, &connection);
    IOObjectRelease(service);
    if (ret != KERN_SUCCESS) {
        errorf("IOServiceOpen failed for class '%s'", kIOFIPSCipherService);
        return connection;
    }

    return connection;
}

static int cavs_dispatch_kernel_op(cavs_vector vector, void *request, size_t request_len,
        uint8_t *result, size_t *result_len)
{
    if (cavs_dispatch_kernel_connection == 0) {
        errorf("Opening connection to kernel");
        cavs_dispatch_kernel_connection = cavs_dispatch_kernel_setup(kIOFIPSCipherService);
    }

    if (cavs_dispatch_kernel_connection == 0) {
        errorf("failed kernel connection");
        return CAVS_STATUS_FAIL;
    }

    kern_return_t ret = IOConnectCallStructMethod(cavs_dispatch_kernel_connection,
            vector, request, request_len, result, result_len);
    if (ret != KERN_SUCCESS) {
        return CAVS_STATUS_FAIL;
    }

    return CAVS_STATUS_OK;
}

int cavs_dispatch_kernel(cavs_vector vector, uint8_t *request_buf,
        size_t request_len, void *result, size_t *result_len)
{
    /*
     * Share the result between the cavs_kernel_send and cavs_kernel_receive calls.
     */
    int ret = cavs_dispatch_kernel_op(vector, request_buf, request_len, result, result_len);
    if (ret != CAVS_STATUS_OK) {
        errorf("failed kernel send");       /* Sometimes intentionally reported for bad parameters. */
        *result_len = 0;
    }

    return ret;
}
