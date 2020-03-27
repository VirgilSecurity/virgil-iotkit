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

#ifndef VS_LOCK_H
#define VS_LOCK_H

#include <virgil/iot/threadsafe/vs-lock-hal.h>

#ifdef __cplusplus
namespace VirgilIoTKit {
extern "C" {
#endif

typedef struct {
    vs_lock_ctx_t r_counter_lock;
    vs_lock_ctx_t w_lock;
    uint32_t r_counter;
} vs_rwlock_t;

vs_status_e
vs_threadsafe_rwlock_init(vs_rwlock_t *mtx);

vs_status_e
vs_threadsafe_rwlock_deinit(vs_rwlock_t *mtx);

vs_status_e
vs_threadsafe_rwlock_rdlock(vs_rwlock_t *mtx);

vs_status_e
vs_threadsafe_rwlock_rdunlock(vs_rwlock_t *mtx);

vs_status_e
vs_threadsafe_rwlock_wrlock(vs_rwlock_t *mtx);

vs_status_e
vs_threadsafe_rwlock_wrunlock(vs_rwlock_t *mtx);

#ifdef __cplusplus
} // extern "C"
} // namespace VirgilIoTKit
#endif

#endif // VS_LOCK_H
