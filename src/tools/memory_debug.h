//
// Created by DiaLight on 6/13/2026.
//

#ifndef FLAME_MEMORY_DEBUG_H
#define FLAME_MEMORY_DEBUG_H


namespace memory_debug {

    void *dbg_malloc(size_t size, bool protectFromUnderrun = false);
    bool is_dbg(void *ptr);
    void *dbg_realloc(void *ptr, size_t size);
    void dbg_free(void *ptr);
    size_t dbg_size(void *ptr);

};


#endif //FLAME_MEMORY_DEBUG_H
