//
// Created by DiaLight on 11/20/2025.
//

#include "MyVersionInfo.h"

bool MyVersionInfo::open() {
    wchar_t filePath[MAX_PATH];
    GetModuleFileNameW(hModule, filePath, MAX_PATH);
    DWORD dwHandle;
    DWORD vSize = GetFileVersionInfoSizeW(filePath, &dwHandle);
    if (vSize == 0) return false;
    cbVersionInfo = vSize + 1;
    versionInfo = malloc(vSize + 1);
    if (!GetFileVersionInfoExW(FILE_VER_GET_NEUTRAL, filePath, dwHandle, vSize, versionInfo)) return false;
    if (!VerQueryValueW(versionInfo, L"\\VarFileInfo\\Translation", (LPVOID*) &lpTranslate, &cbTranslate)) return false;
    return true;
}
std::string MyVersionInfo::queryValue(const char* csEntry) const {
    for(unsigned int i = 0; i < (cbTranslate / sizeof(LANGANDCODEPAGE)); i++) {
        if(lpTranslate[i].wLanguage != LANGID_US_ENGLISH) continue;
        char subblock[256];
        sprintf_s(subblock, "\\StringFileInfo\\%04x%04x\\%s", lpTranslate[i].wLanguage, lpTranslate[i].wCodePage, csEntry);
        char *description = NULL;
        UINT dwBytes;
        if(VerQueryValue(versionInfo, subblock, (LPVOID*) &description, &dwBytes)) {
            return (char *) description;
        }
    }
    return "";
}
