//
// Created by DiaLight on 09.08.2024.
//
#include "dk2/RegKey.h"
#include "patches/micro_patches.h"
#include "gog_cfg.h"
#include "gog_patch.h"


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


int *dk2::RegKey::settings_readValue(int *pstatus, LPCSTR lpValueName, uint32_t *pValue) {
    if(gog::RegistryConfig_patch::enable) {
        if (gog::cfg::patchRegistryConfig(pstatus, lpValueName, (DWORD *) pValue) != -1) return pstatus;
    }
    if (!lpValueName || this->key == NULL) {
        *pstatus = -1;
        return pstatus;
    }
    DWORD Type = 0;
    DWORD value;
    DWORD cbData = sizeof(value);
    if(RegQueryValueExA(this->key, lpValueName, NULL, &Type, (LPBYTE) &value, &cbData) != ERROR_SUCCESS) {
        *pstatus = -1;
        return pstatus;
    }
    signed int v8_type;
    if (RegQueryValueExA(this->key, lpValueName, NULL, &Type, NULL, NULL) != ERROR_SUCCESS) {
        HKEY tmp;
        if (RegOpenKeyA(this->key, lpValueName, &tmp)) {
            v8_type = -1;
        } else {
            RegCloseKey(tmp);
            v8_type = -2;
        }
    } else {
        v8_type = Type;
    }
    if (v8_type == REG_DWORD || v8_type == REG_DWORD_BIG_ENDIAN) {
        *pValue = value;
        *pstatus = 0;
        return pstatus;
    }
    if (v8_type == REG_LINK) {
        *pValue = _byteswap_ulong(value);
        *pstatus = 0;
        return pstatus;
    }
    *pstatus = -1;
    return pstatus;
}