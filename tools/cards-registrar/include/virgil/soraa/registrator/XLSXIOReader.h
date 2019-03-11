/**
 * Copyright (C) 2018 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef VIRGIL_DEMO_SORAA_LAMP_REGISTRATOR_XLSXIOREADER_H
#define VIRGIL_DEMO_SORAA_LAMP_REGISTRATOR_XLSXIOREADER_H


#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>
#include <string>
#include "xlsxio_read.h"

namespace virgil {
    namespace soraa {
        namespace registrator {

            class XLSXIOReader {

            private:
                xlsxioreader handle;

                xlsxioreadersheet sheethandle;

            public:

                XLSXIOReader(const char *filename);

                ~XLSXIOReader();

                bool OpenSheet(const char *sheetname, unsigned int flags);

                bool ReopenSheet(const char *sheetname, unsigned int flags);

                bool GetNextRow();
                char *GetNextCell();

                bool GetNextCellString(std::string &value);
                bool GetNextCellInt(int64_t &value);

                int GetColumnNumberByContent(std::string &content, int startCellNum);

                bool GetCellString(std::string &value, int columnNum, int startCellNum);

                XLSXIOReader &operator>>(char *&value);
                XLSXIOReader &operator>>(std::string &value);
                XLSXIOReader &operator>>(int64_t &value);
                XLSXIOReader &operator>>(double &value);

            };
        }
    }
}

#endif //VIRGIL_DEMO_SORAA_LAMP_REGISTRATOR_XLSXIOREADER_H
