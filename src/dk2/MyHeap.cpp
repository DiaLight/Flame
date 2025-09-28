//
// Created by DiaLight on 9/28/2025.
//

#include "dk2/MyHeapEntry.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/big_resolution_fix/big_resolution_fix.h"


void *__cdecl dk2::MyHeap_alloc(int a1_size) {
    if(patch::big_resolution_fix::enabled) {
        //  return HeapAlloc(hHeap, HEAP_ZERO_MEMORY, a1_size);
        void *ptr = _aligned_malloc(a1_size, 0x100);
        ZeroMemory(ptr, a1_size);
        return ptr;
    }
    void *result = (void *)MyHeap_alloc_impl(a1_size);
    if ( result )
        return result;
    int v2_autoremoved = MyHeap_autoremoveObjects();
    result = (void *)MyHeap_alloc_impl(a1_size);
    if ( result )
        return result;
    while ( v2_autoremoved )
    {
        v2_autoremoved = MyHeap_autoremoveObjects();
        result = (void *)MyHeap_alloc_impl(a1_size);
        if ( result )
            return result;
    }
    MyHeap_size += 0x200000;
    char Buffer[256];
    sprintf(Buffer, "Increasing Engine Heap Size To %d Megs", MyHeap_size / 1024 / 1024);
    void *v3_buf = _malloc_1(0x200020u);
    int v4_idx = MyHeap_increaseCount;
    MyHeap_bufArr[MyHeap_increaseCount] = v3_buf;
    if ( !MyHeap_bufArr )
        exit(-1);
    int v5 = 6;
    do
        ++v5;
    while ( 1 << v5 < 0x200000 );
    int v6_idx = (((~((1 << (v5 - 3)) - 1) & 0x200000) - (1 << (v5 - 1))) >> (v5 - 3)) + 4 * (v5 - 1);
    if ( v4_idx == 32 )
        exit(-1);
    MyHeapEntry *v7 = (MyHeapEntry *)((char *)MyHeap_bufArr[v4_idx] + 0x20);
    *(int *) &v7 &= ~0x1F;
    MyHeap_increaseBlocks[v4_idx] = v7;
    v7->fC = 0x200000;
    MyHeap_increaseBlocks[MyHeap_increaseCount]->f12 = 0;
    MyHeap_increaseBlocks[MyHeap_increaseCount]->f4 = 0;
    MyHeap_increaseBlocks[MyHeap_increaseCount]->f8 = 0;
    MyHeap_increaseBlocks[MyHeap_increaseCount]->f10 = v6_idx;
    MyHeap_increaseBlocks[MyHeap_increaseCount]->f13 = 1;
    MyHeap_increaseBlocks[MyHeap_increaseCount]->f0 = MyHeap__blockArr[v6_idx];
    bool v8 = MyHeap__blockIdx < v6_idx;
    MyHeap__blockArr[v6_idx] = MyHeap_increaseBlocks[MyHeap_increaseCount];
    if ( v8 )
        MyHeap__blockIdx = v6_idx;
    ++MyHeap_increaseCount;
    result = (void *)MyHeap_alloc_impl(a1_size);
    if ( !result )
        exit(-1);
    return result;
}

void __cdecl dk2::MyHeap_free(void *a1_ptr) {
    if(patch::big_resolution_fix::enabled) {
        //  HeapFree(hHeap, 0, a1_ptr);
        _aligned_free(a1_ptr);
        return;
    }
    if (a1_ptr) {
        MyHeapEntry* v1_entry = (MyHeapEntry*) ((char*) a1_ptr - 20);
        char v2 = 0;
        MyHeapEntry* v3_entry = (MyHeapEntry*) ((char*) a1_ptr + *((DWORD*) a1_ptr - 2) - 20);
        if (!*((char*) a1_ptr - 1) && !v3_entry->f12) {
            v2 = 1;
            if (v3_entry->f0)
                v3_entry->f0->f4 = v3_entry->f4;
            MyHeapEntry* v4 = v3_entry->f4;
            if (v4)
                v4->f0 = v3_entry->f0;
            else
                MyHeap__blockArr[v3_entry->f10] = v3_entry->f0;
            v1_entry->fC += v3_entry->fC;
            v1_entry->f13 = v3_entry->f13;
        }
        MyHeapEntry* v5_entry = v1_entry->f8;
        if (v5_entry && !v5_entry->f12) {
            v2 = 1;
            if (v5_entry->f0)
                v5_entry->f0->f4 = v5_entry->f4;
            MyHeapEntry* v6 = v5_entry->f4;
            if (v6)
                v6->f0 = v5_entry->f0;
            else
                MyHeap__blockArr[v5_entry->f10] = v5_entry->f0;
            v5_entry->fC += v1_entry->fC;
            v5_entry->f13 = v1_entry->f13;
            v1_entry = v5_entry;
        }
        if (v2) {
            if (!v1_entry->f13)
                *(MyHeapEntry**) ((char*) &v1_entry->f8 + v1_entry->fC) = v1_entry;
            __int16 v7 = 6;
            signed int v8 = (v1_entry->fC + 63) & ~0x3Fu;
            if (v8 > 64) {
                do
                    ++v7;
                while (1 << v7 < v8);
            }
            v1_entry->f10 = (((v8 & ~((1 << (v7 - 3)) - 1)) - (1 << (v7 - 1))) >> (v7 - 3)) + 4 * (v7 - 1);
        }
        v1_entry->f12 = 0;
        unsigned __int16 v9 = v1_entry->f10;
        v1_entry->f4 = 0;
        if (MyHeap__blockArr[v9])
            MyHeap__blockArr[v9]->f4 = v1_entry;
        int v10 = v1_entry->f10;
        v1_entry->f0 = MyHeap__blockArr[v10];
        MyHeap__blockArr[v10] = v1_entry;
    }
}

