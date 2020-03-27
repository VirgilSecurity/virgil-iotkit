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
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>

#include <virgil/iot/macros/macros.h>
#include <virgil/iot/threadsafe/vs-lock.h>

/******************************************************************************/
vs_lock_ctx_t
vs_threadsafe_init_hal(void) {
    pthread_mutex_t *mtx;

    mtx = malloc(sizeof(pthread_mutex_t));
    CHECK_NOT_ZERO(mtx);

    CHECK(0 == pthread_mutex_init(mtx, NULL), "Error init mutex var %s (%d)", strerror(errno), errno);

    return mtx;

terminate:
    free(mtx);
    return NULL;
}

/******************************************************************************/
vs_status_e
vs_threadsafe_deinit_hal(vs_lock_ctx_t ctx) {
    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    pthread_mutex_destroy((pthread_mutex_t *)ctx);

    free(ctx);

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_threadsafe_lock_hal(vs_lock_ctx_t ctx) {
    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_RET(0 == pthread_mutex_lock((pthread_mutex_t *)ctx), VS_CODE_ERR_THREAD, "Can't take mutex");

    return VS_CODE_OK;
}

/******************************************************************************/
vs_status_e
vs_threadsafe_unlock_hal(vs_lock_ctx_t ctx) {
    CHECK_NOT_ZERO_RET(ctx, VS_CODE_ERR_NULLPTR_ARGUMENT);

    CHECK_RET(0 == pthread_mutex_unlock((pthread_mutex_t *)ctx), VS_CODE_ERR_THREAD, "Can't release mutex");

    return VS_CODE_OK;
}
/******************************************************************************/
