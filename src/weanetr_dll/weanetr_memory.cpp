//
// Created by DiaLight on 10.01.2025.
//
#include "weanetr_memory.h"


void *net::_malloc(size_t size) {
    return ::malloc(size);
}

void net::_free(void *buf) {
    return ::free(buf);
}

void *net::operator_new(size_t size) {  // ??2@YAPAXI@Z
    return operator new(size);
}

void net::operator_delete(void *buf) {  // ??3@YAXPAX@Z
    operator delete(buf);
}
