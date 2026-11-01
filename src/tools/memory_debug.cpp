//
// Created by DiaLight on 6/13/2026.
//

#include "memory_debug.h"
#include "patches/logging.h"
#include "last_error.h"
#include <Windows.h>
#include <cstdint>
#include <string>

#define DBG_MAGIC 0xFEDACAFE

namespace {
    DWORD g_pageSize;

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
        }
    } init;
}


// simple overrun catch mechanism
void *memory_debug::dbg_malloc(size_t size, bool protectFromUnderrun) {
    size_t totalSize = size + sizeof(debug_info_t);
    size_t sizeWithGuardPages = align_up(totalSize, g_pageSize) + 2 * g_pageSize;

    void *segm = VirtualAlloc(
            NULL,
            sizeWithGuardPages,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE
    );
    if (segm == NULL) {
        DWORD lastError = GetLastError();
        std::string err = FormatLastError(lastError);
        patch::log::err("failed to allocate sz=0x%X err=%08X(%s)", size, lastError, err.c_str());
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
bool memory_debug::is_dbg(void *ptr) {
    if((((size_t) ptr) & 0xF000) == 0) return false;
    return ((debug_info_t *) ptr)[-1].magic == DBG_MAGIC;
}
void *memory_debug::dbg_realloc(void *ptr, size_t size) {
    void *newPtr = memory_debug::dbg_malloc(size);
    if(newPtr) {
        size_t oldSize = memory_debug::dbg_size(ptr);
        if(size > oldSize) {
            memcpy(newPtr, ptr, oldSize);
            memset((uint8_t *) newPtr + oldSize, 0, size - oldSize);
        } else {
            memcpy(newPtr, ptr, size);
        }
    }
    memory_debug::dbg_free(ptr);
    return newPtr;
}
void memory_debug::dbg_free(void *ptr) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD OldProtect;

    VirtualQuery(ptr, &mbi, sizeof(mbi));
    // leave pages in reserved state, but free the physical memory
    VirtualFree(mbi.AllocationBase, 0, MEM_DECOMMIT);
    // protect the address space, so noone can access those pages
    VirtualProtect(mbi.AllocationBase, mbi.RegionSize, PAGE_NOACCESS, &OldProtect);
}
size_t memory_debug::dbg_size(void *ptr) {
    return ((debug_info_t *) ptr)[-1].size;
}


namespace heap_debug {  // another implementation, same approach

    const size_t PAGE_SIZE = 4096;

    void *malloc(size_t size) {
        size_t allocSize = sizeof(void *) + sizeof(size_t) + size;
        size_t alignedSize = (allocSize + (PAGE_SIZE - 1)) & ~(PAGE_SIZE - 1);
        auto *base = (uint8_t *) VirtualAlloc(NULL, alignedSize + PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!base) throw std::exception("oom");

        DWORD oldProtect;
        VirtualProtect(base + alignedSize, PAGE_SIZE, PAGE_NOACCESS, &oldProtect);

        auto *ptr = base + alignedSize - size;
        *(size_t*) (ptr - sizeof(size_t)) = size;
        *(void **) (ptr - sizeof(size_t) - sizeof(void *)) = base;
        return ptr;
    }
    void free(void *ptr) {
        auto size = *(size_t *) ((uint8_t *) ptr - sizeof(size_t));
        auto *base = *(void **) ((uint8_t *) ptr - sizeof(size_t) - sizeof(void *));
        DWORD oldProtect;
        VirtualProtect((uint8_t *) ptr + size, PAGE_SIZE, PAGE_READWRITE, &oldProtect);
        VirtualFree(base, 0, MEM_RELEASE);
    }

}
