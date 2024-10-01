//
// Created by DiaLight on 29.09.2024.
//

#ifndef FLAME_WRITE_PROTECT_H
#define FLAME_WRITE_PROTECT_H

#include <Windows.h>
#include <cstdint>
#include <exception>
#include <cstdio>

class write_protect {
    void *ptr;
    size_t size;
    DWORD prot;
public:
    explicit write_protect(void *ptr, size_t size = sizeof(uint32_t)) : ptr(ptr), size(size), prot(0) {
        if(!VirtualProtect(ptr, size, PAGE_EXECUTE_READWRITE, &prot)) {
            DWORD lastError = GetLastError();
            printf("[error]: VirtualProtect failed. code=%08X\n", lastError);
            throw std::exception();
        }
    }
    ~write_protect() {
        DWORD ignore;
        if(!VirtualProtect(ptr, size, prot, &ignore)) {
            DWORD lastError = GetLastError();
            printf("[error]: VirtualProtect back failed. code=%08X\n", lastError);
        }
    }
};

#endif //FLAME_WRITE_PROTECT_H
