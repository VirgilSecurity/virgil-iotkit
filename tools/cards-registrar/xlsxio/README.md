XLSX I/O
========
Cross-platform C library for reading values from and writing values to .xlsx files.

Description
-----------
XLSX I/O aims to provide a C library for reading and writing .xlsx files.
The .xlsx file format is the native format used by Microsoft(R) Excel(TM) since version 2007.

Goal
----
The library was written with the following goals in mind:
- written in standard C, but allows being used by C++
- simple interface
- small footprint
- portable across different platforms (Windows, *nix)
- minimal dependancies: only depends on expat (only for reading) and minizip or libzip (which in turn depend on zlib)
- separate library for reading and writing .xlsx files
- does not require Microsoft(R) Excel(TM) to be installed

Reading .xlsx files:
- intended to process .xlsx files as a data table, which assumes the following:
  + assumes the first row contains header names
  + assumes the next rows contain values in the same columns as where the header names are supplied
  + only values are processed, anything else is ignored (formulas, layout, graphics, charts, ...)
- the entire shared string table is loaded in memory (warning: could be large for big spreadsheets with a lot of different values)
- supports .xlsx files without shared string table
- worksheet data itself is read on the fly without the need to buffer data in memory
- 2 methods are provided
  + a simple method that allows the application to iterate trough rows and cells
  + an advanced method (with less overhead) which calls callback functions for each cell and after each row

Writing .xlsx files:
- intended for writing data tables as .xlsx files, which assumes the following:
  + only support for writing data (no support for formulas, layout, graphics, charts, ...)
  + no support for multiple worksheets (only one worksheet per file)
- on the fly file generation without the need to buffer data in memory
- no support for shared strings (all values are written as inline strings)

Libraries
---------

The following libraries are provided:
- `-lxlsxio_read` - library for reading .xlsx files, requires `#include <xlsxio_read.h>`
- `-lxlsxio_write` - library for writing .xlsx files, requires `#include <xlsxio_write.h>`
- `-lxlsxio_readw` - experimental library for reading .xlsx files, linked with `-lexpatw`, requires `#define XML_UNICODE` before `#include <xlsxio_read.h>`

Command line utilities
----------------------
Some command line utilities are included:
- `xlsxio_xlsx2csv` - converts all sheets in all specified .xlsx files to individual CSV (Comma Separated Values) files.
- `xlsxio_csv2xlsx` - converts all specified CSV (Comma Separated Values) files to .xlsx files.

Dependancies
------------
This project has the following depencancies:
- [expat](http://www.libexpat.org/) (only for libxlsxio_read)
- [minizip](http://www.winimage.com/zLibDll/minizip.html) or [libzip](http://www.nih.at/libzip/) (libxlsxio_read and libxlsxio_write)

Note that minizip is preferred, as there have been reports that .xlsx files generated with XLSX I/O built against libzip can't be opened with LibreOffice.

There is no dependancy on Microsoft(R) Excel(TM).

XLSX I/O was written with cross-platform portability in mind and works on multiple operating systems, including Windows, macOS and Linux.

Building from source
--------------------
Requirements:
- a C compiler like gcc or clang, on Windows MinGW and MinGW-w64 are supported
- the dependancy libraries (see Dependancies)
- a shell environment, on Windows MSYS is supported
- the make command
- CMake version 2.6 or higher (optional, but preferred)

There are 2 methods to build XLSX I/O:
- using the basic Makefile included
- using CMake (preferred)

Building with make
- build and install by running `make install` optionally followed by:
  + `PREFIX=<path>` - Base path were files will be installed (defaults to /usr/local)
  + `WITH_LIBZIP=1` - Use libzip instead of minizip
  + `WIDE=1` - Also build UTF-16 library (xlsxio_readw)
  + `STATICDLL=1` - Build a static DLL (= doesn't depend on any other DLLs) - only supported on Windows

Building with CMake (preferred method)
- configure by running `cmake -G"Unix Makefiles"` (or `cmake -G"MSYS Makefiles"` on Windows) optionally followed by:
  + `-DCMAKE_INSTALL_PREFIX:PATH=<path>` Base path were files will be installed
  + `-DBUILD_STATIC:BOOL=OFF` - Don't build static libraries
  + `-DBUILD_SHARED:BOOL=OFF` - Don't build shared libraries
  + `-DBUILD_TOOLS:BOOL=OFF` - Don't build tools (only libraries)
  + `-DBUILD_EXAMPLES:BOOL=OFF` - Don't build examples
  + `-DWITH_LIBZIP:BOOL=ON` - Use libzip instead of Minizip
  + `-DWITH_WIDE:BOOL=ON` - Also build UTF-16 library (libxlsxio_readw)
- build and install by running `make install` (or `make install/strip` to strip symbols)

For Windows prebuilt binaries are also available for download (both 32-bit and 64-bit)

Example C programs
------------------
### Reading from an .xlsx file
```c
#include <xlsxio_read.h>
```
```c
//open .xlsx file for reading
xlsxioreader xlsxioread;
if ((xlsxioread = xlsxioread_open(filename)) == NULL) {
  fprintf(stderr, "Error opening .xlsx file\n");
  return 1;
}

//read values from first sheet
char* value;
xlsxioreadersheet sheet;
const char* sheetname = NULL;
printf("Contents of first sheet:\n");
if ((sheet = xlsxioread_sheet_open(xlsxioread, sheetname, XLSXIOREAD_SKIP_EMPTY_ROWS)) != NULL) {
  //read all rows
  while (xlsxioread_sheet_next_row(sheet)) {
    //read all columns
    while ((value = xlsxioread_sheet_next_cell(sheet)) != NULL) {
      printf("%s\t", value);
      free(value);
    }
    printf("\n");
  }
  xlsxioread_sheet_close(sheet);
}

//clean up
xlsxioread_close(xlsxioread);
```
### Listing all worksheets in an .xlsx file
```c
#include <xlsxio_read.h>
```
```c
//open .xlsx file for reading
xlsxioreader xlsxioread;
if ((xlsxioread = xlsxioread_open(filename)) == NULL) {
  fprintf(stderr, "Error opening .xlsx file\n");
  return 1;
}

//list available sheets
xlsxioreadersheetlist sheetlist;
const char* sheetname;
printf("Available sheets:\n");
if ((sheetlist = xlsxioread_sheetlist_open(xlsxioread)) != NULL) {
  while ((sheetname = xlsxioread_sheetlist_next(sheetlist)) != NULL) {
    printf(" - %s\n", sheetname);
  }
  xlsxioread_sheetlist_close(sheetlist);
}

//clean up
xlsxioread_close(xlsxioread);
```
### Writing to an .xlsx file
```c
#include <xlsxio_write.h>
```
```c
//open .xlsx file for writing (will overwrite if it already exists)
xlsxiowriter handle;
if ((handle = xlsxiowrite_open(filename, "MySheet")) == NULL) {
  fprintf(stderr, "Error creating .xlsx file\n");
  return 1;
}

//write column names
xlsxiowrite_add_column(handle, "Col1", 16);
xlsxiowrite_add_column(handle, "Col2", 0);
xlsxiowrite_next_row(handle);

//write data
int i;
for (i = 0; i < 1000; i++) {
  xlsxiowrite_add_cell_string(handle, "Test");
  xlsxiowrite_add_cell_int(handle, i);
  xlsxiowrite_next_row(handle);
}

//close .xlsx file
xlsxiowrite_close(handle);
```

License
-------
XLSX I/O is released under the terms of the MIT License (MIT), see LICENSE.txt.

This means you are free to use XLSX I/O in any of your projects, from open source to commercial.

This library does not require Microsoft(R) Excel(TM) to be installed.
