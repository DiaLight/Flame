//
// Created by DiaLight on 19.01.2025.
//

#include "logging.h"
#include <cstdarg>
#include <cstdio>

void patch::log::dbg(const char *format, ...) {
    va_list args;
    va_start(args, format);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), format, args);
    printf("[d] %s\n", msg);
    va_end(args);
}

void patch::log::spmsg(const char *format, ...) {
//    va_list args;
//    va_start(args, format);
//    char msg[1024];
//    vsnprintf(msg, sizeof(msg), format, args);
//    printf("[spmsg] %s\n", msg);
//    va_end(args);
}

void patch::log::sock(const char *format, ...) {
    va_list args;
    va_start(args, format);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), format, args);
    printf("[sock] %s\n", msg);
    va_end(args);
}

void patch::log::data(const char *format, ...) {  // guaranteed data
//    va_list args;
//    va_start(args, format);
//    char msg[1024];
//    vsnprintf(msg, sizeof(msg), format, args);
//    printf("[data] %s\n", msg);
//    va_end(args);
}
void patch::log::gdata(const char *format, ...) {  // guaranteed data
//    va_list args;
//    va_start(args, format);
//    char msg[1024];
//    vsnprintf(msg, sizeof(msg), format, args);
//    printf("[gdata] %s\n", msg);
//    va_end(args);
}

void patch::log::err(const char *format, ...) {
    va_list args;
    va_start(args, format);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), format, args);
    printf("[err] %s\n", msg);
    va_end(args);
}

