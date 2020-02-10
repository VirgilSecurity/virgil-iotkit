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

// (с) https://github.com/swansontec/map-macro

#ifndef AP_SECURITY_SDK_LOGGER_MACRO_VA_ARGS_START_H
#define AP_SECURITY_SDK_LOGGER_MACRO_VA_ARGS_START_H

#define VS_IOT_EVAL0(...) __VA_ARGS__
#define VS_IOT_EVAL1(...) VS_IOT_EVAL0(VS_IOT_EVAL0(VS_IOT_EVAL0(__VA_ARGS__)))
#define VS_IOT_EVAL2(...) VS_IOT_EVAL1(VS_IOT_EVAL1(VS_IOT_EVAL1(__VA_ARGS__)))
#define VS_IOT_EVAL3(...) VS_IOT_EVAL2(VS_IOT_EVAL2(VS_IOT_EVAL2(__VA_ARGS__)))
#define VS_IOT_EVAL4(...) VS_IOT_EVAL3(VS_IOT_EVAL3(VS_IOT_EVAL3(__VA_ARGS__)))
/*
#define VS_IOT_EVAL5(...) VS_IOT_EVAL4(VS_IOT_EVAL4(VS_IOT_EVAL4(__VA_ARGS__)))
#define VS_IOT_EVAL6(...) VS_IOT_EVAL5(VS_IOT_EVAL5(VS_IOT_EVAL5(__VA_ARGS__)))
#define VS_IOT_EVAL7(...) VS_IOT_EVAL6(VS_IOT_EVAL6(VS_IOT_EVAL6(__VA_ARGS__)))
#define VS_IOT_EVAL8(...) VS_IOT_EVAL7(VS_IOT_EVAL7(VS_IOT_EVAL7(__VA_ARGS__)))
#define VS_IOT_EVAL9(...) VS_IOT_EVAL8(VS_IOT_EVAL8(VS_IOT_EVAL8(__VA_ARGS__)))
*/
#define VS_IOT_EVAL(...) VS_IOT_EVAL4(VS_IOT_EVAL4(VS_IOT_EVAL4(__VA_ARGS__)))

#define VS_IOT_MAP_END(...)
#define VS_IOT_MAP_OUT
#define VS_IOT_MAP_COMMA ,

#define VS_IOT_MAP_GET_END2() 0, VS_IOT_MAP_END
#define VS_IOT_MAP_GET_END1(...) VS_IOT_MAP_GET_END2
#define VS_IOT_MAP_GET_END(...) VS_IOT_MAP_GET_END1
#define VS_IOT_MAP_NEXT0(test, next, ...) next VS_IOT_MAP_OUT
#define VS_IOT_MAP_NEXT1(test, next) VS_IOT_MAP_NEXT0(test, next, 0)
#define VS_IOT_MAP_NEXT(test, next) VS_IOT_MAP_NEXT1(VS_IOT_MAP_GET_END test, next)

#define VS_IOT_MAP0(f, x, peek, ...) f(x) VS_IOT_MAP_NEXT(peek, VS_IOT_MAP1)(f, peek, __VA_ARGS__)
#define VS_IOT_MAP1(f, x, peek, ...) f(x) VS_IOT_MAP_NEXT(peek, VS_IOT_MAP0)(f, peek, __VA_ARGS__)

#define VS_IOT_MAP_LIST_NEXT1(test, next) VS_IOT_MAP_NEXT0(test, VS_IOT_MAP_COMMA next, 0)
#define VS_IOT_MAP_LIST_NEXT(test, next) VS_IOT_MAP_LIST_NEXT1(VS_IOT_MAP_GET_END test, next)

#define VS_IOT_MAP_LIST0(f, x, peek, ...) f(x) VS_IOT_MAP_LIST_NEXT(peek, VS_IOT_MAP_LIST1)(f, peek, __VA_ARGS__)
#define VS_IOT_MAP_LIST1(f, x, peek, ...) f(x) VS_IOT_MAP_LIST_NEXT(peek, VS_IOT_MAP_LIST0)(f, peek, __VA_ARGS__)

/**
 * Applies the function macro `f` to each of the remaining parameters.
 */
#define VS_IOT_MAP(f, ...) VS_IOT_EVAL(VS_IOT_MAP1(f, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

/**
 * Applies the function macro `f` to each of the remaining parameters and
 * inserts commas between the results.
 */
#define VS_IOT_MAP_LIST(f, ...) EVAL(VS_IOT_MAP_LIST1(f, __VA_ARGS__, ()()(), ()()(), ()()(), 0))

#endif // AP_SECURITY_SDK_LOGGER_MACRO_VA_ARGS_START_H
