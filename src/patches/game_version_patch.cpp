//
// Created by DiaLight on 06.08.2024.
//

#include "game_version_patch.h"
#include <Windows.h>
#include <cstdio>

bool game_version_patch::enabled = true;

bool resolveFileVersion(char *out) {
    bool status = false;
    CHAR szVersionFile[MAX_PATH];
    GetModuleFileNameA(NULL, szVersionFile, sizeof(szVersionFile));

    DWORD verHandle = 0;
    DWORD verSize = GetFileVersionInfoSizeA( szVersionFile, &verHandle);
    if (verSize != NULL) {
        LPSTR verData = new char[verSize];
        if (GetFileVersionInfoA( szVersionFile, verHandle, verSize, verData)) {
            UINT uiSize;
            BYTE* lpb;
            if( VerQueryValueA(
                    verData, "\\VarFileInfo\\Translation",
                    (void**)&lpb, &uiSize)) {
                WORD* lpw = (WORD *) lpb;

                char strQuery[256];
                snprintf(strQuery, 256, "\\StringFileInfo\\%04x%04x\\FileVersion", lpw[0], lpw[1]);
                if(VerQueryValue(
                        verData, const_cast<LPSTR>( (LPCSTR)strQuery ),
                        (void**)&lpb, &uiSize) && uiSize > 0) {
                    LPCSTR version = (LPCSTR)lpb;
                    printf("%s\n", version);
                    if(LPCSTR pos = strstr(version, "build")) {
                        char ver[64];
                        char build[64];
                        strncpy(ver, version, pos - version - 1);
                        ver[pos - version - 1] = '\0';
                        strcpy(build, pos);
                        sprintf(out, " V%s\n %s", ver, build);
                        status = true;
                    }
                }
            }
        }
        delete[] verData;
    }
    return status;
}

namespace {
    char versionCache[64] = {0};
}

char *game_version_patch::getFileVersion() {
    if(!enabled) return nullptr;
    if(versionCache[0] == '\0') if(!resolveFileVersion(versionCache)) enabled = false;
    if(versionCache[0] == '\0') return nullptr;
    return versionCache;
}
