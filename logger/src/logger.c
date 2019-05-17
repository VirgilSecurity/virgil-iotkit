//
// Created by Oleksandr Nemchenko on 2019-05-17.
//

#include "logger.h"

void vs_logger_start(const char *msg){
    (void)msg;
    vs_logger_print_hal(msg);
}
