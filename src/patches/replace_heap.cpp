//
// Created by DiaLight on 9/23/2025.
//

#include "replace_heap.h"
#include <Windows.h>
#include <cstdint>
#include <vector>
#include "patches/logging.h"

#define DBG_MAGIC 0xFEDACAFE

namespace {
    DWORD g_pageSize;

    HANDLE g_dbgHeap = NULL;

    void ProtectMemRegion(void* region_ptr, size_t sizeWithGuardPages) {
        size_t preRegionGuardPageAddress = (size_t) region_ptr;
        size_t postRegionGuardPageAddress = (size_t) (region_ptr) + sizeWithGuardPages - g_pageSize;

        DWORD flOldProtect1;
        VirtualProtect(
            (void *) (preRegionGuardPageAddress),
            g_pageSize,
            PAGE_NOACCESS,
            &flOldProtect1
        );

        DWORD flOldProtect2;
        VirtualProtect(
            (void *) (postRegionGuardPageAddress),
            g_pageSize,
            PAGE_NOACCESS,
            &flOldProtect2
        );
    }

    size_t align_up(size_t v, size_t a) {
        return (v + a - 1) / a * a;
    }
    size_t align_down(size_t v, size_t a) {
        return v / a * a;
    }

    struct debug_info_t {
        size_t size;
        size_t magic;
    };

    struct _init {
        _init() {
            SYSTEM_INFO sysInfo;
            GetSystemInfo(&sysInfo);
            g_pageSize = sysInfo.dwPageSize;
            g_dbgHeap = HeapCreate(HEAP_GENERATE_EXCEPTIONS, 0x10000, 0);
        }
    } init;
}


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

    // simple overrun catch mechanism
    void *malloc_virt(size_t size, bool protectFromUnderrun = false) {
        size_t totalSize = size + sizeof(debug_info_t);
        size_t sizeWithGuardPages = align_up(totalSize, g_pageSize) + 2 * g_pageSize;

        void *segm = VirtualAlloc(
            NULL,
            sizeWithGuardPages,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
        );
        if (segm == NULL) {
            patch::log::err("failed to allocate sz=0x%X err=%08X", size, GetLastError());
            return NULL;
        }
        ProtectMemRegion(segm, sizeWithGuardPages);

        void *ptr;
        if (protectFromUnderrun) {
            size_t allocStart = (size_t) segm + g_pageSize;
            ptr = (void *) (allocStart + sizeof(debug_info_t));
        } else {
            size_t allocEnd = (size_t) segm + sizeWithGuardPages - g_pageSize;
            ptr = (void *) align_down(allocEnd - totalSize + sizeof(debug_info_t), sizeof(size_t));
        }
        auto &info = ((debug_info_t *) ptr)[-1];
        info.magic = DBG_MAGIC;
        info.size = size;
        memset(ptr, 0, size);
        return ptr;
    }
    bool is_virt(void *ptr) {
        return false;
        if((((size_t) ptr) & 0xF000) == 0) return false;
        return ((debug_info_t *) ptr)[-1].magic == DBG_MAGIC;
    }
    void *realloc_virt(void *ptr, size_t size) {
        void *newPtr = replace_heap::malloc(size);
        if(newPtr) {
            size_t oldSize = replace_heap::size(ptr);
            if(size > oldSize) {
                memcpy(newPtr, ptr, oldSize);
                memset((uint8_t *) newPtr + oldSize, 0, size - oldSize);
            } else {
                memcpy(newPtr, ptr, size);
            }
        }
        replace_heap::free(ptr);
        return newPtr;
    }
    void free_virt(void *ptr) {
        MEMORY_BASIC_INFORMATION mbi;
        DWORD OldProtect;

        VirtualQuery(ptr, &mbi, sizeof(mbi));
        // leave pages in reserved state, but free the physical memory
        VirtualFree(mbi.AllocationBase, 0, MEM_DECOMMIT);
        // protect the address space, so noone can access those pages
        VirtualProtect(mbi.AllocationBase, mbi.RegionSize, PAGE_NOACCESS, &OldProtect);
    }
    size_t size_virt(void *ptr) {
        return ((debug_info_t *) ptr)[-1].size;
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
    if(!is_virt(ptr)) {
        return realloc_win(ptr, size);
    }
    return realloc_virt(ptr, size);
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
    if(!is_virt(ptr)) {
        free_win(ptr);
        return;
    }
    free_virt(ptr);
}

size_t patch::replace_heap::size(void *ptr) {
    if(!is_virt(ptr)) {
        return size_win(ptr);
    }
    return size_virt(ptr);
}

