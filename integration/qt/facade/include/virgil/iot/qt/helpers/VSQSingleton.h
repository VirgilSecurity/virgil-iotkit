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

/*! \file VSQSingleton.h
 * \brief Singleton implementation
 *
 * #VSQSingleton is the singleton implementation. Its minimum usage is simple:
 * \code

class YourClass :
    public VSQSingleton<YourClass> {    // public inheritance
    friend VSQSingleton<YourClass>;     // Singleton has to be friend to call constructor

    void member();                      // Some class member
private:
    YourClass();                        // Private constructor that has to be called by VSQSingleton<YourClass> only
};

YourClass::instance().member();         // Class usage
 * \endcode
 *
 * #VSQIoTKitFacade, #VSQSnapInfoClient, #VSQSnapInfoClientQml use #VSQSingleton.
 *
 */

#ifndef VIRGIL_IOTKIT_QT_SINGLETON_H
#define VIRGIL_IOTKIT_QT_SINGLETON_H

#include <type_traits>

/** Singleton implementation
 *
 * You can use \a D parameter as derived from \a T
 * \tparam T Base class for \a D
 * \tparam D Class to be singleton
 */
template <typename T, typename D = T> class VSQSingleton {
    friend D;
    static_assert(std::is_base_of<T, D>::value, "T should be a base type for D");

public:
    /** Get static instance
     *
     * Creates once \a D class instance and returns its base class \a T
     * \return
     */
    static T &
    instance() {
        static D inst;
        return inst;
    }

private:
    VSQSingleton() = default;
    ~VSQSingleton() = default;
    VSQSingleton(const VSQSingleton &) = delete;
    VSQSingleton &
    operator=(const VSQSingleton &) = delete;
};

#endif // VIRGIL_IOTKIT_QT_SINGLETON_H
