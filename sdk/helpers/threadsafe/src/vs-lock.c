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

#include <stdint.h>

#include <virgil/iot/threadsafe/vs-lock.h>
#include <virgil/iot/macros/macros.h>

/******************************************************************************/
vs_status_e
vs_threadsafe_rwlock_init(vs_rwlock_t *mtx) {
    CHECK_NOT_ZERO_RET(mtx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    mtx->r_counter = 0;
    mtx->r_counter_lock = vs_threadsafe_init_hal();
    CHECK_RET(NULL != mtx->r_counter_lock, VS_CODE_ERR_NOINIT, "Error initialize r_counter_lock");

    mtx->w_lock = vs_threadsafe_init_hal();
    CHECK(mtx->w_lock, "Error initialize w_lock");

    return VS_CODE_OK;

terminate:
    vs_threadsafe_deinit_hal(mtx->r_counter_lock);
    return VS_CODE_ERR_NOINIT;
}

/******************************************************************************/
vs_status_e
vs_threadsafe_rwlock_deinit(vs_rwlock_t *mtx) {
    vs_status_e ret_code;
    CHECK_NOT_ZERO_RET(mtx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    ret_code = vs_threadsafe_deinit_hal(mtx->r_counter_lock);
    if (VS_CODE_OK != ret_code) {
        VS_LOG_ERROR("Error deinit r_counter_lock");
    }
    ret_code = vs_threadsafe_deinit_hal(mtx->w_lock);
    if (VS_CODE_OK != ret_code) {
        VS_LOG_ERROR("Error deinit w_lock");
    }

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_threadsafe_rwlock_rdlock(vs_rwlock_t *mtx) {
    vs_status_e ret_code;
    CHECK_NOT_ZERO_RET(mtx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    ret_code = vs_threadsafe_lock_hal(mtx->r_counter_lock);
    VS_IOT_ASSERT(VS_CODE_OK == ret_code);
    CHECK_RET(VS_CODE_OK == ret_code, ret_code, "Can't take r_counter_lock");

    if (mtx->r_counter == UINT32_MAX) {
        VS_LOG_ERROR("r_counter has a MAX value!");
        goto terminate;
    }

    ++mtx->r_counter;

    if (mtx->r_counter == 1) {
        ret_code = vs_threadsafe_lock_hal(mtx->w_lock);
        VS_IOT_ASSERT(VS_CODE_OK == ret_code);
        if (VS_CODE_OK != ret_code) {
            mtx->r_counter = 0;
            VS_LOG_ERROR("Can't take w_lock");
            goto terminate;
        }
    }

    VS_LOG_INFO("RD_LOCK. r_counter = %u", mtx->r_counter);

terminate:

    ret_code = vs_threadsafe_unlock_hal(mtx->r_counter_lock);
    VS_IOT_ASSERT(VS_CODE_OK == ret_code);
    CHECK_RET(VS_CODE_OK == ret_code, ret_code, "Can't release r_counter_lock");

    return ret_code;
}

/******************************************************************************/
vs_status_e
vs_threadsafe_rwlock_rdunlock(vs_rwlock_t *mtx) {
    vs_status_e ret_code;
    CHECK_NOT_ZERO_RET(mtx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    ret_code = vs_threadsafe_lock_hal(mtx->r_counter_lock);
    VS_IOT_ASSERT(VS_CODE_OK == ret_code);
    CHECK_RET(VS_CODE_OK == ret_code, ret_code, "Can't take r_counter_lock");

    if (mtx->r_counter == 0) {
        VS_LOG_ERROR("r_counter is equal zero!");
        goto terminate;
    }

    --mtx->r_counter;
    if (mtx->r_counter == 0) {
        ret_code = vs_threadsafe_unlock_hal(mtx->w_lock);
        VS_IOT_ASSERT(VS_CODE_OK == ret_code);
        if (VS_CODE_OK != ret_code) {
            mtx->r_counter = 1;
            VS_LOG_ERROR("Can't release w_lock");
            goto terminate;
        }
    }
    VS_LOG_INFO("RD_UNLOCK. r_counter = %u", mtx->r_counter);

terminate:
    ret_code = vs_threadsafe_unlock_hal(mtx->r_counter_lock);
    VS_IOT_ASSERT(VS_CODE_OK == ret_code);
    CHECK_RET(VS_CODE_OK == ret_code, ret_code, "Can't release r_counter_lock");

    return ret_code;
}

/******************************************************************************/
vs_status_e
vs_threadsafe_rwlock_wrlock(vs_rwlock_t *mtx) {
    vs_status_e ret_code;
    CHECK_NOT_ZERO_RET(mtx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    STATUS_CHECK_RET(vs_threadsafe_lock_hal(mtx->w_lock), "Can't take w_lock");
    VS_LOG_INFO("RW_LOCK");
    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_threadsafe_rwlock_wrunlock(vs_rwlock_t *mtx) {
    vs_status_e ret_code;
    CHECK_NOT_ZERO_RET(mtx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    STATUS_CHECK_RET(vs_threadsafe_unlock_hal(mtx->w_lock), "Can't release w_lock");
    VS_LOG_INFO("RW_UNLOCK");
    return VS_CODE_OK;
}