//
// Created by DiaLight on 10.01.2025.
//
#include "dk2_memory.h"
#include "dk2_functions.h"

void *dk2::call_malloc(size_t size) {
    return dk2::_malloc(size);
}

void dk2::call_free(void *buf) {
    dk2::_free(buf);
}

void *dk2::operator_new(size_t size) {  // ??2@YAPAXI@Z
    return dk2::__nh_malloc(size, 1);
}

void dk2::operator_delete(void *buf) {  // ??3@YAXPAX@Z
    dk2::_free(buf);
}
