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
#include <AssertMacros.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <sys/kauth.h>

#include <sys/conf.h>
#include <miscfs/devfs/devfs.h>
#include <sys/systm.h>

#include <IOKit/IODeviceTreeSupport.h>
#include <libkern/OSMalloc.h>

extern "C" {
#include "cavs_common.h"
#include "cavs_driver_generic.h"
}

#include "cavs_kext_service.h"
#include "cavs_kext_client.h"

OSDefineMetaClassAndStructors(IOFIPSCipherUserClient, IOUserClient);

static IOReturn cavs_kernel_map_buffer(IOMemoryDescriptor *mdesc, uint8_t **buffer, IOMemoryMap **mmap, bool ro);

bool IOFIPSCipherUserClient::initWithTask(task_t owningTask, void *security_id, UInt32 type)
{
    if (!owningTask) {
        errorf("no owning task");
        return false;
    }

    if (!IOUserClient::initWithTask(owningTask, security_id, type)) {
        errorf("initWithTask return false");
        return false;
    }

    if (clientHasPrivilege(security_id, kIOClientPrivilegeAdministrator) != kIOReturnSuccess) {
        errorf("Insufficient privileges to access kext.");
        return false;
    }

    m_task = owningTask;
    m_provider = NULL;

    return true;
}

bool IOFIPSCipherUserClient::start(IOService *provider)
{
    // Call the super
    if (!IOUserClient::start(provider)) {
        errorf("IOUserClient::start return false");
        return false;
    }

    // cache the provider which should be an instance of the IOFIPSCipherService class
    if ((m_provider = OSDynamicCast(IOFIPSCipherService, provider)) == NULL) {
        errorf("OSDynamicCast(IOFIPSCipherService, provider) failed");
        return false;
    }


    return true;
}

IOReturn IOFIPSCipherUserClient::clientClose()
{
    return terminate();
}

IOReturn IOFIPSCipherUserClient::externalMethod(uint32_t selector,
        IOExternalMethodArguments *arguments,
        IOExternalMethodDispatch *dispatch, OSObject *target, void *reference)
{
    IOReturn result = kIOReturnInvalid;
    int ret;

    IOMemoryMap *input_map = NULL;
    uint8_t *input_buf;
    size_t input_buf_len;

    IOMemoryMap *output_map;
    uint8_t *output_buf;
    size_t output_buf_len;

    if (arguments == NULL) {
        errorf("no arguments supplied");
        return kIOReturnBadArgument;
    }

    if (m_provider == NULL) {
        errorf("no provider supplied");
        return kIOReturnInternalError;
    }

    if (arguments->structureOutputDescriptor == NULL) {
        errorf("no result buffer supplied");
        return kIOReturnBadArgument;
    }

    /* Map in the input and output memory segments directly. */
    if (arguments->structureInputDescriptor) {
        result = cavs_kernel_map_buffer(arguments->structureInputDescriptor,
                &input_buf, &input_map, true);
        if (result != KERN_SUCCESS) {
            errorf("failed to map input buffer");
            return kIOReturnInternalError;
        }
        input_buf_len = arguments->structureInputDescriptor->getLength();
    } else {
        input_buf = (uint8_t *)arguments->structureInput;
        input_buf_len = arguments->structureInputSize;
    }

    result = cavs_kernel_map_buffer(arguments->structureOutputDescriptor,
            &output_buf, &output_map, false);
    if (result != kIOReturnSuccess) {
        errorf("failed to map input buffer");
        if (arguments->structureInputDescriptor) {
            arguments->structureInputDescriptor->complete();
            input_map->unmap();
        }
        return kIOReturnInternalError;
    }
    output_buf_len = arguments->structureOutputDescriptorSize;

    /* Dispatch the vector, storing the output in the mapped segments. */
    ret = cavs_generic_cavs_request(input_buf, input_buf_len, output_buf,
            &output_buf_len);
    if (ret == CAVS_STATUS_FAIL) {
        result = kIOReturnInternalError;
    } else {
        result = kIOReturnSuccess;
    }

    /* Save the output results. */
    arguments->structureOutputDescriptorSize = output_buf_len;

    /* Close all of the outstanding memory mappings. */
    if (arguments->structureInputDescriptor) {
        input_map->release();
        arguments->structureInputDescriptor->complete();
    }

    output_map->release();
    arguments->structureOutputDescriptor->complete();

    return result;
}

static IOReturn cavs_kernel_map_buffer(IOMemoryDescriptor *mdesc, uint8_t **buffer, IOMemoryMap **mmap, bool ro)
{
    *mmap = NULL;

    IOReturn result;

    *buffer = NULL;

    result = mdesc->prepare();
    if (result != kIOReturnSuccess) {
        errorf("invalid mdesc->prepare()");
        return result;
    }

    *mmap = mdesc->map(ro ? kIOMapReadOnly : 0);
    if (*mmap == NULL) {
        errorf("failed mmap");
        mdesc->complete();
        return kIOReturnError;
    }

    *buffer = reinterpret_cast<uint8_t *>((*mmap)->getVirtualAddress());
    if (*buffer == NULL) {
        errorf("getVirtualAddress failed");
        mdesc->complete();
        (*mmap)->unmap();
        return kIOReturnBadArgument;
    }

    return kIOReturnSuccess;
}
