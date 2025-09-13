//
// Created by DiaLight on 9/14/2025.
//

#include "logging.h"
#include <Windows.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <fstream>

namespace {
    bool g_log_initialized = false;
    DWORD g_start_tick = 0;
}

void loader::log::init() {
    if(g_log_initialized) return;
    g_log_initialized = true;
    g_start_tick = GetTickCount();
    {  // clear latest file
        std::ofstream ofs("flame/latest.log", std::ios::out );
        ofs.close();
    }
}

char *print_time(char *pch) {
    loader::log::init();
    DWORD val = GetTickCount() - g_start_tick;
    DWORD ms = val % 1000;
    val /= 1000;
    DWORD sec = val % 60;
    val /= 60;
    DWORD min = val % 60;
    val /= 60;
    DWORD hours = val;
    int len = sprintf(pch, "%02i:%02i:%02i.%04i", hours, min, sec, ms);
    if(len < 0) return pch;
    return pch + len;
}
char *print_s(char *pch, const char *s) {
    size_t len = strlen(s);
    strcpy(pch, s);
    return pch + len;
}

void vlog(const char *level, const char *format, va_list args) {
    char msg[2048];
    char *pch = msg;
    pch = print_time(pch);
    pch = print_s(pch, " [");
    pch = print_s(pch, level);
    pch = print_s(pch, "] ");
    char *conStart = pch;
    int len = vsnprintf(pch, sizeof(msg), format, args);
    if(len < 0) pch = print_s(pch, format);
    else pch += len;
    pch[0] = '\0';
    fprintf(stdout, "%s\n", conStart);
    {
        std::ofstream ofs("flame/latest.log", std::ios::out | std::ios::app);
        ofs << msg << '\n';
        ofs.close();
    }
}


void loader::log::inf(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vlog("inf", format, args);
    va_end(args);
}

void loader::log::err(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vlog("err", format, args);
    va_end(args);
}

void loader::log::warn(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vlog("warn", format, args);
    va_end(args);
}

