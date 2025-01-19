//
// Created by DiaLight on 22.01.2023.
//

#ifndef EMBER_GOG_DEBUG_H
#define EMBER_GOG_DEBUG_H

#include <cstdio>

void _gog_print(const char *msg);

#define gog_debug(msg) _gog_print(msg);

#define gog_debugf(format, ...) { \
    char msg_buf[1024]; \
    wsprintfA(msg_buf, format, __VA_ARGS__); \
    _gog_print(msg_buf); \
}

#endif //EMBER_GOG_DEBUG_H
