//
// Created by DiaLight on 9/14/2025.
//

#ifndef FLAME_LOGGING_H
#define FLAME_LOGGING_H


#include <cstdarg>

namespace loader::log {

    void init();

    void inf(const char *format, ...);
    void err(const char *format, ...);
    void warn(const char *format, ...);

}

#define fname(fmt, ...) "%s: " fmt, __FUNCTION__, __VA_ARGS__

#define log_inf(fmt, ...) loader::log::inf(fname(fmt, __VA_ARGS__))
#define log_err(fmt, ...) loader::log::err(fname(fmt, __VA_ARGS__))
#define log_warn(fmt, ...) loader::log::warn(fname(fmt, __VA_ARGS__))


#endif // FLAME_LOGGING_H
