//
// Created by DiaLight on 16.08.2024.
//

#include "game_version.h"
#include <Windows.h>
#include <cstdio>

const char *DK2Version_toString(int ver) {
    switch(ver) {
        case 130: return "v1.30";  // aka 1.00
        case 151: return "v1.51";
        case 170: return "v1.70";
    }
    return "unknown";
}

bool readSignature2(HANDLE hFile, DWORD &size, DWORD &entryPoint) {
    size = GetFileSize(hFile, NULL);
    if (size == INVALID_FILE_SIZE) {
        printf("GetFileSize error: %08X\n", GetLastError());
        return false;
    }
    if (size < 0x400) return false;
    char headers[0x400];
    DWORD read = 0;
    if (!ReadFile(hFile, headers, sizeof(headers), &read, NULL) || read != sizeof(headers)) {
        printf("ReadFile error: %08X\n", GetLastError());
        return false;
    }
    auto *dos = (IMAGE_DOS_HEADER *) headers;
    auto *nt = (IMAGE_NT_HEADERS32 *) (headers + dos->e_lfanew);
    entryPoint = nt->OptionalHeader.AddressOfEntryPoint;
    return true;
}

bool readSignature(DWORD &size, DWORD &entryPoint) {
    wchar_t exePath[MAX_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_PATH);
    HANDLE hFile = CreateFileW(exePath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("CreateFileW error: %08X\n", GetLastError());
        return false;
    }
    bool ret = readSignature2(hFile, size, entryPoint);
    CloseHandle(hFile);
    return ret;
}

int getDK2Version(DWORD entry, DWORD size) {
    int ver = 0;
    // entry=003A0046 size=0077005C
    if (entry == 0x00229F50 && (size & ~0xFF) == 0x002C9800) {
        ver = 130;
    } else if (entry == 0x00238440 && (size & ~0xFF) == 0x002D6E00) {
        ver = 170;
    } else if (entry == 0x00238440 && size == 0x002D9630) {  // steam
        ver = 170;
    } else if (entry == 0x00232D90 && (
            (size & ~0xFF) == 0x002D2A00 ||  // official
            (size & ~0xFF) == 0x002D0A00  // GIM
    )) {
        ver = 151;
    }
    return ver;
}


int dk2_version = 0;

bool initGameVersion() {
    DWORD size = 0, entry = 0;
    if (!readSignature(size, entry)) {
        printf("failed to read signature\n");
        return false;
    }
    printf("signature: entry=%08X size=%08X\n", entry, size);
    int ver = getDK2Version(entry, size);
    printf("Dungeon Keeper 2 version: %s\n", DK2Version_toString(ver));
    if(ver == 0) return false;
    dk2_version = ver;
    return true;
}
