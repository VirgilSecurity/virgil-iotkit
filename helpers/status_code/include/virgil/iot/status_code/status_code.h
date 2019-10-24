//  Copyright (C) 2015-2019 Virgil Security, Inc.
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
 * This file declares \ref vs_status_e status codes and macroses to simplify return code checks.
 */

#ifndef VS_IOT_SDK_STATUS_CODE
#define VS_IOT_SDK_STATUS_CODE

#include <virgil/iot/macros/macros.h>

/** Status code
 * Status code to be returned from function. Zero value \ref VS_CODE_OK is used for non-error values. All others mean error
 */
typedef enum {
    VS_CODE_COMMAND_NO_RESPONSE = 100,
    VS_CODE_OLD_VERSION = 1,
    VS_CODE_OK = 0, /**< Successful operation */
    VS_CODE_ERR_NULLPTR_ARGUMENT = -1, /**< Argument is NULL pointer while it must be non NULL */
    VS_CODE_ERR_ZERO_ARGUMENT = -2, /**< Argument is zero while it must be non zero */
    VS_CODE_ERR_INCORRECT_ARGUMENT = -3, /**< Incorrect argument */
    VS_CODE_ERR_INCORRECT_PARAMETER = -4, /**< Incorrect parameter */
    VS_CODE_ERR_UNSUPPORTED_PARAMETER = -5, /**< Unsupported parameter */
    VS_CODE_ERR_AMBIGUOUS_INIT_CALL = -6, /**< Ambiguous initialization call */
    VS_CODE_ERR_CTX_NOT_READY = -7, /**< Context is not ready */
    VS_CODE_ERR_NOT_IMPLEMENTED = -8, /**< This feature is not implemented */
    VS_CODE_ERR_NOT_FOUND = -9, /**< Entity has not been found */

    VS_CODE_ERR_NO_CALLBACK = -10, /**< There is no callback */
    VS_CODE_ERR_UNREGISTERED_MAPPING_TYPE = -11, /**< Unsupporter mapping type */
    VS_CODE_ERR_INCORRECT_SEND_REQUEST = -12, /**< Incorrect sed request */

    VS_CODE_ERR_NO_MEMORY = -20, /**< No memory */
    VS_CODE_ERR_TOO_SMALL_BUFFER = -21, /**< Buffer is too small */
    VS_CODE_ERR_FORMAT_OVERFLOW = -22, /**< Incorrect data format */

    VS_CODE_ERR_VERIFY = -30, /**< Incorrect result of verifying */
    VS_CODE_ERR_UNSUPPORTED = -31, /**< Unsupported crypto data */
    VS_CODE_ERR_CRYPTO = -32, /**< Error during crypto operation processing */

    VS_CODE_ERR_FILE = -40, /**< Error during file processing */
    VS_CODE_ERR_FILE_READ = -41, /**< Error during file read */
    VS_CODE_ERR_FILE_WRITE = -42, /**< Error during file write */
    VS_CODE_ERR_FILE_DELETE = -43, /**< Error during file delete */

    VS_CODE_ERR_CLOUD = -50, /**< Error during operation with cloud */
    VS_CODE_ERR_JSON = -51, /**< Error during JSON processing */
    VS_CODE_ERR_REQUEST_PREPARE = -52, /**< Error during request preparation */
    VS_CODE_ERR_REQUEST_SEND = -53, /**< Error during request send */

    VS_CODE_ERR_PRVS_UNKNOWN = -60, /**< Provision error */

    VS_CODE_ERR_SDMP_UNKNOWN = -70, /**< SDMP error */
    VS_CODE_ERR_SDMP_NOT_MY_PACKET = -71, /**< SDMP error "not my packet" */
    VS_CODE_ERR_SDMP_TOO_MUCH_SERVICES = -72, /**< Too much services to be registred by SDMP */

    VS_CODE_ERR_THREAD = -80, /**< Error during thread processing */
    VS_CODE_ERR_NO_SIMULATOR = -81, /**< No sumilator has been found */
    VS_CODE_ERR_SOCKET = -82, /**< Error during socket operations */
    VS_CODE_ERR_PLC = -83, /**< PLC error */
    VS_CODE_ERR_NOINIT = -84, /**< Not initialized */

} vs_status_e;

/** Status code check and goto if non-successful.
 *
 *  1. \a OPERATION is compared with \ref VS_CODE_OK.
 *  2. If they are not equal, \a MESSAGES is logged and function jumps to terminate label.
 *
 * \warning terminate label must be present in current function.
 *
 *  \param[in] OPERATION Operation to be checked.
 *  \param[in] MESSAGE String with printf-like parameter to be logged in case of non-successful operation.
 */
#define STATUS_CHECK(OPERATION, MESSAGE, ...)   CHECK(VS_CODE_OK == (OPERATION), (MESSAGE), ##__VA_ARGS__)

/** Status code check and return \ref vs_status_e if non-successful.
 *
 *  1. \a OPERATION result code is saved to the \ref vs_status_e ret_code variable.
 *  2. if ret_code is not equal to \ref VS_CODE_OK, \a MESSAGES is logged and function returns ret_code.
 *
 * \warning \ref vs_status_e ret_code must be initialized.
 *
 *  \param[in] OPERATION Operation to be checked.
 *  \param[in] MESSAGE String with printf-like parameter to be logged in case of non-successful operation.
 *
 *  \return OPERATION's \ref vs_status_e ret_code in case of non-successful result.
 */
#define STATUS_CHECK_RET(OPERATION, MESSAGE, ...)   CHECK_RET(VS_CODE_OK == (ret_code = (OPERATION)), ret_code, (MESSAGE), ##__VA_ARGS__)

/** Status code check and return bool if non-successful.
 *
 *  1. \a OPERATION is compared with \ref VS_CODE_OK.
 *  2. If they are not equal, \a MESSAGES is logged and function returns false.
 *
 *  \param[in] OPERATION Operation to be checked.
 *  \param[in] MESSAGE String with printf-like parameter to be logged in case of non-successful operation.
 *
 *  \return false in case of non-successful result.
 */
#define STATUS_CHECK_RET_BOOL(OPERATION, MESSAGE, ...)   BOOL_CHECK_RET(VS_CODE_OK == (OPERATION), (MESSAGE), ##__VA_ARGS__)

#endif // VS_IOT_SDK_STATUS_CODE
