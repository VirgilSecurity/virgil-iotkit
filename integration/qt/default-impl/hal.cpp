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

#include <iostream>
#include <string>
#include <QStandardPaths>
#include <qdir.h>
#include <QCoreApplication>

QFile VsLogFile;
bool VsLogErr=false;

bool vs_logger_check_file() {

    if(VsLogErr)
        return false;

    if(!VsLogFile.isOpen()) {
        const QDir AppDir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
        qDebug("Create app data dir [%s]", qPrintable(AppDir.absolutePath()));
        if (!AppDir.mkpath(".")) {
            qFatal("Failed to create writable directory at %s", qPrintable(AppDir.absolutePath()));
            VsLogErr=true;
            return false;
        }
        VsLogFile.setFileName(AppDir.absolutePath() + "/" + QCoreApplication::applicationName() + ".log");
        qDebug("Create log file [%s]", qPrintable(VsLogFile.fileName()));
        if (!VsLogFile.open(QIODevice::WriteOnly | QIODevice::Text))
            qFatal("Error create log file [%s]", qPrintable(VsLogFile.fileName()));
        VsLogErr=true;
        return false;
    }

    return true;
}

extern "C" bool
vs_logger_output_hal(const char *buffer) {
    (void)buffer;
    if(!vs_logger_check_file()) {
      VsLogFile.write(buffer,strlen(buffer));
      VsLogFile.flush();
    } else {
      std::cout << buffer << std::flush;
    }
    return true;
}

extern "C" void
vs_impl_msleep(size_t msec) {
    (void)msec;
}
