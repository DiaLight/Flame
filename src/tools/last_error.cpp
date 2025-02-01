//
// Created by DiaLight on 02.02.2025.
//

#include "last_error.h"
#include <Windows.h>


std::string FormatLastError(uint32_t lastError) {
    if(lastError == 0) return {};
    LPSTR messageBuffer = nullptr;
    size_t size = FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER |
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, lastError,
            MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT),
            (LPSTR)&messageBuffer, 0,
            NULL
    );
    std::string message(messageBuffer, size);
    LocalFree(messageBuffer);
    return message;
}

std::string GetLastErrorAsString() {
    return FormatLastError(::GetLastError());
}
