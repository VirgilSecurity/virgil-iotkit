/*
 * upd_http_retrieval_thread.h
 *
 *  Created on: Jan 19, 2018
 */

#ifndef UPD_HTTP_RETRIEVAL_THREAD_H_
#define UPD_HTTP_RETRIEVAL_THREAD_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <virgil/iot/firmware/firmware.h>
#include <virgil/iot/update/update.h>

pthread_t *
vs_file_download_start_thread(void);

bool
vs_file_download_get_request(vs_update_file_type_t **request);

#endif // UPD_HTTP_RETRIEVAL_THREAD_H_
