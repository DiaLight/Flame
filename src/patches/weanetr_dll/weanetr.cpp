//
// Created by DiaLight on 09.01.2025.
//

#include "weanetr.h"
#include <Windows.h>
#include <cstdint>
#include <cstdio>
#include <string>
#include <map>
#include "MLDPlay.h"
#include "globals.h"

template<typename T, typename R, typename... Ts>
void *void_cast(R(T::*f)(Ts...)) {
    union {
        R(T::*pf)(Ts...);
        void* p;
    };
    pf = f;
    return p;
}

bool replaceWeanetrImports(uint8_t *base) {
    auto *dos = (IMAGE_DOS_HEADER *) base;
    auto *nt = (IMAGE_NT_HEADERS32 *) (base + dos->e_lfanew);
    auto &importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size == 0) {
        printf("[-] weanetr imports is not found\n");
        return false;
    }
    IMAGE_IMPORT_DESCRIPTOR *weanetr = NULL;
    for(
            auto *desc = (IMAGE_IMPORT_DESCRIPTOR *) (base + importDir.VirtualAddress);
            desc->OriginalFirstThunk != NULL; desc++) {
        char *libname = (char *) (base + desc->Name);
        if(stricmp(libname, "weanetr.dll") != 0) continue;
        weanetr = desc;
    }
    if(weanetr == NULL) {
        printf("[-] weanetr imports is not found\n");
        return false;
    }

    std::map<int, void *> toReplace = {
            {42, void_cast(&net::MLDPlay::SetupConnection)},
            {6, &net::BFAID_MODEM},
            {43, void_cast(&net::MLDPlay::ShutdownNetwork)},
            {44, void_cast(&net::MLDPlay::StartupNetwork)},
            {15, void_cast(&net::MLDPlay::DumpPlayer)},
            {27, void_cast(&net::MLDPlay::GetSessionDesc)},
            {41, void_cast(&net::MLDPlay::SetSessionDesc)},
            {26, void_cast(&net::MLDPlay::GetPlayerInfo)},
            {21, void_cast(&net::MLDPlay::EnumerateServices)},
            {23, void_cast(&net::MLDPlay::GetCurrentMs)},
            {25, void_cast(&net::MLDPlay::GetPlayerDesc)},
            {4, &net::BFAID_INet},
            {11, void_cast(&net::MLDPlay::CreateNetworkAddress)},
            {22, void_cast(&net::MLDPlay::EnumerateSessions)},
            {12, void_cast(&net::MLDPlay::CreateSession)},
            {29, void_cast(&net::MLDPlay::JoinSession)},
            {35, void_cast(&net::MLDPlay::SendChat)},
            {36, void_cast(&net::MLDPlay::SendData)},
            {14, void_cast(&net::MLDPlay::DestroySession)},
            {16, void_cast(&net::MLDPlay::EnableNewPlayers)},
    };

    auto *lookups = (IMAGE_THUNK_DATA *) (base + weanetr->OriginalFirstThunk);
    auto *addressesBase = (IMAGE_THUNK_DATA *) (base + weanetr->FirstThunk);
    auto *addresses = addressesBase;
    for (; lookups->u1.AddressOfData != 0; lookups++, addresses++) {
        uint32_t rva = weanetr->FirstThunk + ((uintptr_t) &addresses->u1.Function - (uintptr_t) addressesBase);
        uint32_t va = nt->OptionalHeader.ImageBase + rva;
        WORD hint;
        std::string name;
        if ((lookups->u1.AddressOfData & IMAGE_ORDINAL_FLAG) != 0) {
            hint = (WORD) lookups->u1.AddressOfData;
        } else {
            auto *byName = (IMAGE_IMPORT_BY_NAME *) (base + lookups->u1.AddressOfData);
            hint = byName->Hint;
            name = byName->Name;
        }
        auto it = toReplace.find(hint);
        if(it == toReplace.end()) {
            printf("[-] replacement for weanetr ordinal is not found\n");
            return false;
        }
        void *value = it->second;
//        printf("  %08X %08X->%08X %d %s\n", va, *(void **) va, value, hint, name.c_str());

        DWORD prot;
        if(!VirtualProtect((void *) va, sizeof(void *), PAGE_READWRITE, &prot)) {
            DWORD lastError = GetLastError();
            printf("[error]: VirtualProtect failed. code=%08X\n", lastError);
            return false;
        }

        *(void **) va = value;

        DWORD ignore;
        if(!VirtualProtect((void *)va, sizeof(void *), prot, &ignore)) {
            DWORD lastError = GetLastError();
            printf("[error]: VirtualProtect back failed. code=%08X\n", lastError);
            return false;
        }
    }
    return true;
}


bool net::init() {
    // this is a temporary dirty solution
    // the best way is to decompile all functions with weanetr.dll usages
    return replaceWeanetrImports((uint8_t *) GetModuleHandleA(NULL));
}

