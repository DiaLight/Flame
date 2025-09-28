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

#define gog_unused_function_called(fun) {gog_debug("Unused function called: " fun); __debugbreak();}
#define gog_assert_failed(msg) {gog_debug("Assertion failed: " msg); __debugbreak();}
#define gog_assert_failed_hr(msg, hr) {gog_debugf("Assertion failed: " msg " with HRESULT 0x%x", hr); __debugbreak();}

#endif //EMBER_GOG_DEBUG_H
