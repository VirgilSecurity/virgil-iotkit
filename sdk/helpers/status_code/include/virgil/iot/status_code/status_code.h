//  Copyright (C) 2015-2020 Virgil Security, Inc.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without
//  modification, are permitted provided that the following conditions are
//  met:
//
//      (1) Redistributions of source code must retain the above copyright
//      notice, this list of conditions and the following disclaimer.
//
//      (2) Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the following disclaimer in
//      the documentation and/or other materials provided with the
//      distribution.
//
//      (3) Neither the name of the copyright holder nor the names of its
//      contributors may be used to endorse or promote products derived from
//      this software without specific prior written permission.
//
//  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
//  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
//  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
//  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
//  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
//  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
//  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
//  IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//
//  Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>

/*! \file status_code.h
 * \brief Status codes and macroses
 *
 * This file declares #vs_status_e status codes. There are also macros to simplify return code checks :
 *
 * \code

    vs_netif_t *netif;
    const vs_mac_addr_t *mac;
    vs_snap_prvs_devi_t *device_info;
    uint16_t buf_sz;
    uint32_t wait_ms;

    // Goto terminate in case of error
    STATUS_CHECK(vs_fldt_client_request_all_files(), "Unable to request all files");

    // Return function in case of error
    STATUS_CHECK_RET(vs_snap_prvs_device_info(netif, mac, device_info, buf_sz, wait_ms), VS_CODE_ERR_INCORRECT_ARGUMENT,
        "Unable to receive device information during %d milliseconds", wait_ms);

    // Error processing
    terminate:

 * \endcode
 *
 * You can introduce your own error codes. They must start from #VS_CODE_ERR_USER code.
 */

#ifndef VS_IOT_SDK_STATUS_CODE
#define VS_IOT_SDK_STATUS_CODE

#include <virgil/iot/macros/macros.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

/** Status code
 *
 * Zero value #VS_CODE_OK is used for non-error values. Negative values mean error
 */
typedef enum {
    VS_CODE_COMMAND_NO_RESPONSE = 100,      /**< No need in response */
    VS_CODE_OLD_VERSION = 1,                /**< Provided file is not newer than the current file */
    VS_CODE_OK = 0,                         /**< Successful operation */
    VS_CODE_ERR_NULLPTR_ARGUMENT = -1,      /**< Argument is NULL pointer while it must be not NULL */
    VS_CODE_ERR_ZERO_ARGUMENT = -2,         /**< Argument is zero while it must be not zero */
    VS_CODE_ERR_INCORRECT_ARGUMENT = -3,    /**< Incorrect argument */
    VS_CODE_ERR_INCORRECT_PARAMETER = -4,   /**< Incorrect parameter */
    VS_CODE_ERR_UNSUPPORTED_PARAMETER = -5, /**< Unsupported parameter */
    VS_CODE_ERR_AMBIGUOUS_INIT_CALL = -6,   /**< Ambiguous initialization call */
    VS_CODE_ERR_CTX_NOT_READY = -7,         /**< Context is not ready */
    VS_CODE_ERR_NOT_IMPLEMENTED = -8,       /**< This feature is not implemented */
    VS_CODE_ERR_NOT_FOUND = -9,             /**< Entity has not been found */

    VS_CODE_ERR_NO_CALLBACK = -10,               /**< There is no callback */
    VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE = -11, /**< Unsupported mapping type */
    VS_CODE_ERR_INCORRECT_SEND_REQUEST = -12,    /**< Incorrect send request */

    VS_CODE_ERR_NO_MEMORY = -20,        /**< No memory */
    VS_CODE_ERR_TOO_SMALL_BUFFER = -21, /**< Buffer is too small */
    VS_CODE_ERR_FORMAT_OVERFLOW = -22,  /**< Incorrect data format */

    VS_CODE_ERR_VERIFY = -30,      /**< Incorrect result of verification */
    VS_CODE_ERR_UNSUPPORTED = -31, /**< Unsupported crypto data */
    VS_CODE_ERR_CRYPTO = -32,      /**< Error during crypto operation processing */

    VS_CODE_ERR_FILE = -40,        /**< Error during file processing */
    VS_CODE_ERR_FILE_READ = -41,   /**< Error during file read */
    VS_CODE_ERR_FILE_WRITE = -42,  /**< Error during file write */
    VS_CODE_ERR_FILE_DELETE = -43, /**< Error during file delete */

    VS_CODE_ERR_CLOUD = -50,           /**< Error during operation with cloud */
    VS_CODE_ERR_JSON = -51,            /**< Error during JSON processing */
    VS_CODE_ERR_REQUEST_PREPARE = -52, /**< Error during request preparation */
    VS_CODE_ERR_REQUEST_SEND = -53,    /**< Error during request send */

    VS_CODE_ERR_PRVS_UNKNOWN = -60, /**< Provision error */

    VS_CODE_ERR_SNAP_UNKNOWN = -70,           /**< SNAP error */
    VS_CODE_ERR_SNAP_NOT_MY_PACKET = -71,     /**< SNAP error "not my packet" */
    VS_CODE_ERR_SNAP_TOO_MUCH_SERVICES = -72, /**< Too much services to be registered by SNAP */
    VS_CODE_ERR_SNAP_TOO_MUCH_NETIFS = -73,   /**< Too much network interfaces to be registered by SNAP */

    VS_CODE_ERR_THREAD = -80,       /**< Error during thread processing */
    VS_CODE_ERR_NO_SIMULATOR = -81, /**< No simulator has been found */
    VS_CODE_ERR_SOCKET = -82,       /**< Error during socket operations */
    VS_CODE_ERR_PLC = -83,          /**< PLC error */
    VS_CODE_ERR_NOINIT = -84,       /**< Not initialized */
    VS_CODE_ERR_QUEUE = -85,        /**< QUEUE error */

    VS_CODE_ERR_INIT_SNAP = -90,           /**< Error while #vs_netif_t . init call */
    VS_CODE_ERR_DEINIT_SNAP = -91,         /**< Error while #vs_netif_t . deinit call */
    VS_CODE_ERR_TX_SNAP = -92,             /**< Error while #vs_netif_t . tx call */
    VS_CODE_ERR_MAC_SNAP = -93,            /**< Error while #vs_netif_t . mac call */
    VS_CODE_ERR_POLLING_INFO_CLIENT = -94, /**< Error while starting polling */

    VS_CODE_ERR_USER = -128 /**< User specific error codes start with this value */

} vs_status_e;

/** Status code check and perform goto terminate if non-successful.
 *
 *  1. \a OPERATION is compared with #VS_CODE_OK.
 *  2. If they are not equal, \a MESSAGES is logged and function jumps to terminate label.
 *
 * \warning terminate label must be present in current function.
 *
 *  \param[in] OPERATION Operation to be checked.
 *  \param[in] MESSAGE String with printf-like parameter to be logged in case of non-successful operation.
 */
#define STATUS_CHECK(OPERATION, MESSAGE, ...) CHECK(VS_CODE_OK == (OPERATION), (MESSAGE), ##__VA_ARGS__)

/** Status code check and return #vs_status_e if non-successful.
 *
 *  1. \a OPERATION result code is saved to the #vs_status_e ret_code variable.
 *  2. if ret_code is not equal to #VS_CODE_OK, \a MESSAGES is logged and function returns ret_code.
 *
 * \warning #vs_status_e ret_code must be initialized.
 *
 *  \param[in] OPERATION Operation to be checked.
 *  \param[in] MESSAGE String with printf-like parameter to be logged in case of non-successful operation.
 *
 *  \return OPERATION's #vs_status_e ret_code in case of non-successful result.
 */
#define STATUS_CHECK_RET(OPERATION, MESSAGE, ...)                                                                      \
    CHECK_RET(VS_CODE_OK == (ret_code = (OPERATION)), ret_code, (MESSAGE), ##__VA_ARGS__)

/** Status code check and return bool if non-successful.
 *
 *  1. \a OPERATION is compared with #VS_CODE_OK.
 *  2. If they are not equal, \a MESSAGES is logged and function returns false.
 *
 *  \param[in] OPERATION Operation to be checked.
 *  \param[in] MESSAGE String with printf-like parameter to be logged in case of non-successful operation.
 *
 *  \return false in case of non-successful result.
 */
#define STATUS_CHECK_RET_BOOL(OPERATION, MESSAGE, ...)                                                                 \
    BOOL_CHECK_RET(VS_CODE_OK == (OPERATION), (MESSAGE), ##__VA_ARGS__)

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_IOT_SDK_STATUS_CODE
