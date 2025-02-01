//
// Created by DiaLight on 19.01.2025.
//

#ifndef FLAME_PATCH_LOGGING_H
#define FLAME_PATCH_LOGGING_H


#include <cstdarg>

#define fname(fmt, ...) "%s: " fmt, __FUNCTION__, __VA_ARGS__

namespace patch::log {

    void dbg(const char *format, ...);

    void spmsg(const char *format, ...);

    void sock(const char *format, ...);

    void data(const char *format, ...);
    void gdata(const char *format, ...);

    void err(const char *format, ...);

    void v_weanetr(const char *format, va_list args);

}


#endif //FLAME_PATCH_LOGGING_H
