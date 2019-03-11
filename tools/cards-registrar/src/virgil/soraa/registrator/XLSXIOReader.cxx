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

#include <virgil/soraa/registrator/XLSXIOReader.h>

using virgil::soraa::registrator::XLSXIOReader;

XLSXIOReader::XLSXIOReader (const char *filename) {
    handle = xlsxioread_open(filename);
}

XLSXIOReader::~XLSXIOReader () {
    xlsxioread_sheet_close(sheethandle);
    xlsxioread_close(handle);
}

bool XLSXIOReader::OpenSheet(const char *sheetname, unsigned int flags) {

    if(NULL == handle
            || (sheethandle = xlsxioread_sheet_open(handle, sheetname, flags)) == NULL) return false;
    return true;
}

bool XLSXIOReader::ReopenSheet(const char *sheetname, unsigned int flags) {
    if(NULL == sheethandle) return false;
    xlsxioread_sheet_close(sheethandle);
    if((sheethandle = xlsxioread_sheet_open(handle, sheetname, flags)) == NULL) return false;
    return true;
}

bool XLSXIOReader::GetNextRow () {
    return (xlsxioread_sheet_next_row(sheethandle) != 0);
}

char* XLSXIOReader::GetNextCell () {
    return xlsxioread_sheet_next_cell(sheethandle);
}

 bool XLSXIOReader::GetNextCellString (std::string& value) {
    char* result;
    if (!xlsxioread_sheet_next_cell_string(sheethandle, &result)) {
        value.clear();
        return false;
    }
    value.assign(result);
    free(result);
    return true;
}

 bool XLSXIOReader::GetNextCellInt (int64_t& value) {
    if (!xlsxioread_sheet_next_cell_int(sheethandle, &value)) {
        value = 0;
        return false;
    }
    return true;
}

 bool XLSXIOReader::GetCellString(std::string& value, int columnNum, int startCellNum) {
    int rowNum = startCellNum;

     while (rowNum < columnNum) {
         if(!GetNextCellString(value)) return false;
         rowNum++;
     }

     if(!GetNextCellString(value)) {
         return false;
     }
    return true;
}

 int XLSXIOReader::GetColumnNumberByContent(std::string& content, int startCellNum) {
    std::string value;
    int rowNum = startCellNum;

    while (GetNextCellString(value)) {
        if(content == value)
            return rowNum;
        rowNum++;
    }
    return -1;
}

XLSXIOReader& XLSXIOReader::operator >> (std::string& value) {
    GetNextCellString(value);
    return *this;
}

XLSXIOReader& XLSXIOReader::operator >> (int64_t& value) {
    GetNextCellInt(value);
    return *this;
}
