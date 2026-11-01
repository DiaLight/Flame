//
// Created by DiaLight on 9/23/2025.
//

#include "replace_heap.h"
#include <Windows.h>
#include <cstdint>
#include <vector>

namespace {

    HANDLE g_dbgHeap = NULL;

}

struct _init {
    _init() {
        g_dbgHeap = HeapCreate(HEAP_GENERATE_EXCEPTIONS, 0x10000, 0);
    }
} init;


namespace patch::replace_heap {
    constexpr bool validate = false;

    void *malloc_win(size_t size) {
        if(validate && !HeapValidate(g_dbgHeap, 0, NULL)) __debugbreak();
        return HeapAlloc(g_dbgHeap, HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, size);
    }
    void *realloc_win(void *ptr, size_t size) {
        return HeapReAlloc(g_dbgHeap, HEAP_ZERO_MEMORY, ptr, size);
    }
    void free_win(void *ptr) {
        if(validate && !HeapValidate(g_dbgHeap, 0, NULL)) __debugbreak();
        HeapFree(g_dbgHeap, HEAP_GENERATE_EXCEPTIONS, ptr);
    }
    size_t size_win(void *ptr) {
        return HeapSize(g_dbgHeap, 0, ptr);
    }

}

bool patch::replace_heap::enabled = true;

void *patch::replace_heap::malloc(size_t size) {
    if(size == 0) return NULL;
    void* ptr = malloc_win(size);
    if(ptr && size > 0x200) {
//        char msg[1024];
//        snprintf(msg, sizeof(msg), "[%d] alloc p=%08X-%08X sz=0x%X",
//                 GetCurrentThreadId(), ptr, (uint8_t *) ptr + size, size);
//        OutputDebugStringA(msg);
    }
    return ptr;
}

void *patch::replace_heap::realloc(void *ptr, size_t size) {
    if(!ptr) return replace_heap::malloc(size);
    return realloc_win(ptr, size);
}

void patch::replace_heap::free(void *ptr) {
    if(ptr == NULL) return;
//    size_t size = memory_debug::size(ptr);
//    if(size > 0x60) {
//        char msg[1024];
//        snprintf(msg, sizeof(msg), "[%d] free p=%08X-%08X sz=0x%X",
//                 GetCurrentThreadId(), ptr, (uint8_t *) ptr + size, size);
//        OutputDebugStringA(msg);
//    }
    free_win(ptr);
}

size_t patch::replace_heap::size(void *ptr) {
    return size_win(ptr);
}

