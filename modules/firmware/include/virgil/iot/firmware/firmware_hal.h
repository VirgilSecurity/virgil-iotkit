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

/*! \file firmware_hal.h
 * \brief Firmware HAL signatures
 *
 * This header contains Firmware HAL signatures that Firmware library uses.
 *
 */

#ifndef VS_FIRMWARE_INTERFACE_H
#define VS_FIRMWARE_INTERFACE_H

#include <virgil/iot/status_code/status_code.h>

/** Prepare space
 *
 * Signature for function that is called by #vs_firmware_install_firmware Firmware library function to prepare space for
 * newly loaded and verified firmware.
 *
 * If filesystem is present, it can be preparing new file name, for example "<app-name>.new" where <app-name> is the
 * application filename. This function should remove filename with this name if it exists.
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_firmware_install_prepare_space_hal(void);

/** Append data
 *
 * Signature for function that is called by #vs_firmware_install_firmware Firmware library function to append data for
 * firmware new installation file.
 *
 * If filesystem is present, it can be opening file and appending \a data to the end.
 *
 * \param[in] data Data to be append
 * \param[in] data_sz Data size
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_firmware_install_append_data_hal(const void *data, uint16_t data_sz);

/** Get own firmware footer
 *
 * Signature for function that is called by #vs_firmware_get_own_firmware_descriptor Firmware library function to get
 * current firmware file footer.
 *
 * Footer is added by virgil-firmware-signer utility at the end of firmware image. This function has to read the end of the self image.
 *
 * \param[out] footer Device footer
 * \param[in] footer_sz Footer size
 *
 * \return #VS_CODE_OK in case of success or error code.
 */
vs_status_e
vs_firmware_get_own_firmware_footer_hal(void *footer, size_t footer_sz);

#endif // VS_FIRMWARE_INTERFACE_H
