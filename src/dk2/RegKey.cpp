//
// Created by DiaLight on 09.08.2024.
//
#include "dk2/RegKey.h"
#include "patches/micro_patches.h"


unsigned int dk2::RegKey::settings_readBytesCount(LPCSTR lpValueName) {
    if ( !lpValueName || !this->key ) return 0;
    use_wasd_by_default_patch::useAlternativeName(lpValueName);
    LSTATUS Value = RegQueryValueExA(this->key, lpValueName, 0, 0, 0, (LPDWORD) &lpValueName);
    return Value == 0 ? (unsigned int)lpValueName : 0;
}

uint32_t *dk2::RegKey::settings_writeBytes(
        uint32_t *pstatus,
        LPCSTR lpValueName,
        uint32_t dwType,
        BYTE *lpData,
        uint32_t cbData) {
    if (!lpData || !this->key || !(lpValueName || dwType == 1)) {
        *pstatus = -1;
        return pstatus;
    }
    use_wasd_by_default_patch::useAlternativeName(lpValueName);
    if (RegSetValueExA(this->key, lpValueName, 0, dwType, lpData, cbData) != 0) {
        *pstatus = -1;
        return pstatus;
    }
    *pstatus = 0;
    return pstatus;
}

uint32_t *__thiscall dk2::RegKey::settings_readBytes(uint32_t *pstatus, LPCSTR lpValueName, LPBYTE lpData, uint32_t cbData) {
    if (!lpValueName || this->key == 0) {
        *pstatus = -1;
        return pstatus;
    }
    use_wasd_by_default_patch::useAlternativeName(lpValueName);
    DWORD type = 0;
    if (RegQueryValueExA(this->key, lpValueName, 0, &type, lpData, (LPDWORD) &cbData) != 0) {
        *pstatus = -1;
        return pstatus;
    }
    *pstatus = 0;
    return pstatus;
}

