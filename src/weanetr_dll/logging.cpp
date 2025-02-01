//
// Created by DiaLight on 09.01.2025.
//

#include <cstdarg>
#include "logging.h"
#include "patches/logging.h"


void net::_log(const char *format, ...) {
    // the original log printing was intentionally removed by the Bullfrog developers,
    // but the log lines were retained

    va_list args;
    va_start(args, format);
    patch::log::v_weanetr(format, args);
    va_end(args);
}

