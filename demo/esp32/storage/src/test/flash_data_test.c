/* Wear levelling and FAT filesystem example.
   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.

   This sample shows how to store files inside a FAT filesystem.
   FAT filesystem is stored in a partition inside SPI flash, using the
   flash wear levelling library.
*/

#include <platform/init/idf/flash_data.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include "esp_spiffs.h"

#define FNM_PERIOD 0x04 // Period must be matched by period.
#define EOS '\0'
#define FNM_LEADING_DIR 0x08 // Ignore /<tail> after Imatch.
#define FNM_NOMATCH 1        // Match failed.
#define FNM_PATHNAME 0x02    // Slash must be matched by slash.
#define FNM_NOESCAPE 0x01    // Disable backslash escaping.
#define FNM_CASEFOLD 0x10    // Case insensitive search.
#define FNM_PREFIX_DIRS 0x20 // Directory prefixes of pattern match too.

//*************************************************************************************************************
static const char *
rangematch(const char *pattern, char test, int flags) {
    int negate, ok;
    char c, c2;

    /*
     * A bracket expression starting with an unquoted circumflex
     * character produces unspecified results (IEEE 1003.2-1992,
     * 3.13.2).  This implementation treats it like '!', for
     * consistency with the regular expression syntax.
     * J.T. Conklin (conklin@ngai.kaleida.com)
     */
    if ((negate = (*pattern == '!' || *pattern == '^')))
        ++pattern;

    if (flags & FNM_CASEFOLD)
        test = tolower((unsigned char)test);

    for (ok = 0; (c = *pattern++) != ']';) {
        if (c == '\\' && !(flags & FNM_NOESCAPE))
            c = *pattern++;
        if (c == EOS)
            return (NULL);

        if (flags & FNM_CASEFOLD)
            c = tolower((unsigned char)c);

        if (*pattern == '-' && (c2 = *(pattern + 1)) != EOS && c2 != ']') {
            pattern += 2;
            if (c2 == '\\' && !(flags & FNM_NOESCAPE))
                c2 = *pattern++;
            if (c2 == EOS)
                return (NULL);

            if (flags & FNM_CASEFOLD)
                c2 = tolower((unsigned char)c2);

            if ((unsigned char)c <= (unsigned char)test && (unsigned char)test <= (unsigned char)c2)
                ok = 1;
        } else if (c == test)
            ok = 1;
    }
    return (ok == negate ? NULL : pattern);
}

//*************************************************************************************************************
static int
fnmatch(const char *pattern, const char *string, int flags) {
    const char *stringstart;
    char c, test;

    for (stringstart = string;;)
        switch (c = *pattern++) {
        case EOS:
            if ((flags & FNM_LEADING_DIR) && *string == '/')
                return (0);
            return (*string == EOS ? 0 : FNM_NOMATCH);
        case '?':
            if (*string == EOS)
                return (FNM_NOMATCH);
            if (*string == '/' && (flags & FNM_PATHNAME))
                return (FNM_NOMATCH);
            if (*string == '.' && (flags & FNM_PERIOD) &&
                (string == stringstart || ((flags & FNM_PATHNAME) && *(string - 1) == '/')))
                return (FNM_NOMATCH);
            ++string;
            break;
        case '*':
            c = *pattern;
            // Collapse multiple stars.
            while (c == '*')
                c = *++pattern;

            if (*string == '.' && (flags & FNM_PERIOD) &&
                (string == stringstart || ((flags & FNM_PATHNAME) && *(string - 1) == '/')))
                return (FNM_NOMATCH);

            // Optimize for pattern with * at end or before /.
            if (c == EOS)
                if (flags & FNM_PATHNAME)
                    return ((flags & FNM_LEADING_DIR) || strchr(string, '/') == NULL ? 0 : FNM_NOMATCH);
                else
                    return (0);
            else if ((c == '/') && (flags & FNM_PATHNAME)) {
                if ((string = strchr(string, '/')) == NULL)
                    return (FNM_NOMATCH);
                break;
            }

            // General case, use recursion.
            while ((test = *string) != EOS) {
                if (!fnmatch(pattern, string, flags & ~FNM_PERIOD))
                    return (0);
                if ((test == '/') && (flags & FNM_PATHNAME))
                    break;
                ++string;
            }
            return (FNM_NOMATCH);
        case '[':
            if (*string == EOS)
                return (FNM_NOMATCH);
            if ((*string == '/') && (flags & FNM_PATHNAME))
                return (FNM_NOMATCH);
            if ((pattern = rangematch(pattern, *string, flags)) == NULL)
                return (FNM_NOMATCH);
            ++string;
            break;
        case '\\':
            if (!(flags & FNM_NOESCAPE)) {
                if ((c = *pattern++) == EOS) {
                    c = '\\';
                    --pattern;
                }
            }
            break;
            // FALLTHROUGH
        default:
            if (c == *string) {
            } else if ((flags & FNM_CASEFOLD) && (tolower((unsigned char)c) == tolower((unsigned char)*string))) {
            } else if ((flags & FNM_PREFIX_DIRS) && *string == EOS &&
                       ((c == '/' && string != stringstart) || (string == stringstart + 1 && *stringstart == '/')))
                return (0);
            else
                return (FNM_NOMATCH);
            string++;
            break;
        }
    // NOTREACHED
    return 0;
}

//*************************************************************************************************************
static void
list(char *path, char *match) {

    DIR *dir = NULL;
    struct dirent *ent;
    char type;
    char size[9];
    char tpath[255];
    char tbuffer[80];
    struct stat sb;
    struct tm *tm_info;
    char *lpath = NULL;
    int statok;

    printf("\nList of Directory [%s]\n", path);
    printf("-----------------------------------\n");
    // Open directory
    dir = opendir(path);
    if (!dir) {
        printf("Error opening directory\n");
        return;
    }

    // Read directory entries
    uint64_t total = 0;
    int nfiles = 0;
    printf("T  Size      Date/Time         Name\n");
    printf("-----------------------------------\n");
    while ((ent = readdir(dir)) != NULL) {
        sprintf(tpath, path);
        if (path[strlen(path) - 1] != '/')
            strcat(tpath, "/");
        strcat(tpath, ent->d_name);
        tbuffer[0] = '\0';

        if ((match == NULL) || (fnmatch(match, tpath, (FNM_PERIOD)) == 0)) {
            // Get file stat
            statok = stat(tpath, &sb);

            if (statok == 0) {
                tm_info = localtime(&sb.st_mtime);
                strftime(tbuffer, 80, "%d/%m/%Y %R", tm_info);
            } else
                sprintf(tbuffer, "                ");

            if (ent->d_type == DT_REG) {
                type = 'f';
                nfiles++;
                if (statok)
                    strcpy(size, "       ?");
                else {
                    total += sb.st_size;
                    if (sb.st_size < (1024 * 1024))
                        sprintf(size, "%8d", (int)sb.st_size);
                    else if ((sb.st_size / 1024) < (1024 * 1024))
                        sprintf(size, "%6dKB", (int)(sb.st_size / 1024));
                    else
                        sprintf(size, "%6dMB", (int)(sb.st_size / (1024 * 1024)));
                }
            } else {
                type = 'd';
                strcpy(size, "       -");
            }

            printf("%c  %s  %s  %s\r\n", type, size, tbuffer, ent->d_name);
        }
    }
    if (total) {
        printf("-----------------------------------\n");
        if (total < (1024 * 1024))
            printf("   %8d", (int)total);
        else if ((total / 1024) < (1024 * 1024))
            printf("   %6dKB", (int)(total / 1024));
        else
            printf("   %6dMB", (int)(total / (1024 * 1024)));
        printf(" in %d file(s)\n", nfiles);
    }
    printf("-----------------------------------\n");

    closedir(dir);

    free(lpath);

    uint32_t tot = 0, used = 0;
    esp_spiffs_info(NULL, &tot, &used);
    printf("SPIFFS: free %u KB of %u KB\n", (tot - used) / 1024, tot / 1024);
    printf("-----------------------------------\n\n");
}

//*************************************************************************************************************
esp_err_t
flash_data_test(void) {
    FILE *f = NULL;
    esp_err_t ret_res = ESP_FAIL;

    flash_data_init("hsm");

    VS_LOG_ERROR("Create dir");

    int res = mkdir("/hsm/data", 0777);
    if (res != 0) {

        printf("  Error creating directory (%d) %s\n", errno, strerror(errno));
        printf("\n");
    }

    VS_LOG_ERROR("List dir /hsm");
    list("/hsm", NULL);

    VS_LOG_ERROR("Opening file");
    f = fopen("/hsm/data/test.txt", "wb");
    if (f == NULL) {
        VS_LOG_ERROR("Failed to open file for writing");
        ret_res = ESP_FAIL;
        goto terminate;
    }

    fprintf(f, "[/hsm/test/test.txt] write file test contents. ESP VER: [%s]\n", esp_get_idf_version());
    fclose(f);
    VS_LOG_ERROR("File written");

    // Open file for reading
    VS_LOG_ERROR("Reading file");
    f = fopen("/hsm/data/test.txt", "rb");
    if (f == NULL) {
        VS_LOG_ERROR("Failed to open file for reading");
        ret_res = ESP_FAIL;
        goto terminate;
    }

    char line[128];
    fgets(line, sizeof(line), f);
    fclose(f);
    // strip newline
    char *pos = strchr(line, '\n');
    if (pos) {
        *pos = '\0';
    }
    VS_LOG_ERROR("Read from file: '%s'", line);

    ret_res = ESP_OK;

terminate:
    return ret_res;
}
