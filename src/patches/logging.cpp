//
// Created by DiaLight on 19.01.2025.
//

#include "logging.h"
#include <cstdarg>
#include <cstdio>
#include <tools/flame_config.h>

flame_config::define_flame_option<bool> o_log_debug(
    "flame:logging:debug",
    "Flame debug logging",
    true
);
void patch::log::dbg(const char *format, ...) {
    if (!o_log_debug.get()) return;
    va_list args;
    va_start(args, format);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), format, args);
    printf("[d] %s\n", msg);
    va_end(args);
}

flame_config::define_flame_option<bool> o_log_ReadSPMessage(
    "flame:logging:readsp",
    "ReadSPMessage function logging",
    false
);
void patch::log::spmsg(const char *format, ...) {
    if (!o_log_ReadSPMessage.get()) return;
    va_list args;
    va_start(args, format);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), format, args);
    printf("[spmsg] %s\n", msg);
    va_end(args);
}

flame_config::define_flame_option<bool> o_log_sock(
    "flame:logging:sock",
    "Network packets logging",
    false
);

void patch::log::sock(const char *format, ...) {
    if (!o_log_sock.get()) return;
    va_list args;
    va_start(args, format);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), format, args);
    printf("[sock] %s\n", msg);
    va_end(args);
}

flame_config::define_flame_option<bool> o_log_data(
    "flame:logging:data",
    "Data packets logging",
    false
);
void patch::log::data(const char *format, ...) {
    if (!o_log_data.get()) return;
    va_list args;
    va_start(args, format);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), format, args);
    printf("[data] %s\n", msg);
    va_end(args);
}

flame_config::define_flame_option<bool> o_log_gdata(
    "flame:logging:gdata",
    "Guaranteed data packets logging",
    false
);
void patch::log::gdata(const char *format, ...) {
    if (!o_log_gdata.get()) return;
    va_list args;
    va_start(args, format);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), format, args);
    printf("[gdata] %s\n", msg);
    va_end(args);
}

flame_config::define_flame_option<bool> o_log_weanetr_err(
    "flame:logging:weanetr_err",
    "",
    true
);
void patch::log::err(const char *format, ...) {
    if (!o_log_weanetr_err.get()) return;
    va_list args;
    va_start(args, format);
    char msg[1024];
    vsnprintf(msg, sizeof(msg), format, args);
    printf("[err] %s\n", msg);
    va_end(args);
}

flame_config::define_flame_option<bool> o_log_weanetr(
    "flame:logging:weanetr",
    "",
    false
);
void patch::log::v_weanetr(const char *format, va_list args) {
    if (!o_log_weanetr.get()) return;
    char msg[1024];
    vsnprintf(msg, sizeof(msg), format, args);
    printf("[weanetr] %s", msg);
}

