//
// Created by DiaLight on 11/20/2025.
//

#ifndef FLAME_MYVERSIONINFO_H
#define FLAME_MYVERSIONINFO_H

#include <Windows.h>
#include <string>

struct MyVersionInfo {
    struct LANGANDCODEPAGE {
        WORD wLanguage;
        WORD wCodePage;
    };

    HMODULE hModule;
    LPVOID versionInfo = NULL;
    UINT cbVersionInfo = 0;
    LANGANDCODEPAGE *lpTranslate = NULL;
    UINT cbTranslate = 0;

    explicit MyVersionInfo(HMODULE hModule) : hModule(hModule) {}
    ~MyVersionInfo() {
        if(versionInfo) free(versionInfo);
    }

    bool open();

#define LANGID_US_ENGLISH 0x0409
    std::string queryValue(const char *csEntry) const;
};


#endif // FLAME_MYVERSIONINFO_H
