//
// Created by DiaLight on 09.08.2024.
//
#include "dk2/RegKey.h"

#include <dk2_globals.h>
#include <patches/registry_to_config.h>

#include "patches/micro_patches.h"
#include "gog_cfg.h"
#include "gog_patch.h"

using Reg2Cfg = patch::registry_to_config::Reg2Cfg;

int *dk2::RegKey::create_BfProdLtd_key(int *pstatus, LPCSTR lpSubKey, BOOL useCurrentUser) {
    if (patch::registry_to_config::enabled) {
        if (this->key) patch::registry_to_config::close((Reg2Cfg *) this->key);
        this->key = (HKEY) patch::registry_to_config::createRoot(lpSubKey);
        *pstatus = this->key ? 0 : -1;
        return pstatus;
    }
    if (this->key && RegCloseKey(this->key) == 0) {
        this->key = NULL;
    }
    HKEY root = useCurrentUser ? HKEY_CURRENT_USER : HKEY_LOCAL_MACHINE;
    HKEY phkResult;
    LSTATUS lstatus = RegCreateKeyExA(root, "Software\\Bullfrog Productions Ltd", 0, NULL, 0, 0xF003Fu, NULL, &phkResult, NULL);
    if (lstatus != 0 || phkResult == NULL) {
        *pstatus = -1;
        return pstatus;
    }
    this->key = phkResult;

    if (lpSubKey) {
        lstatus = RegCreateKeyExA(this->key, lpSubKey, 0, NULL, 0, 0xF003Fu, NULL, &phkResult, NULL);
        RegCloseKey(this->key);
        if (lstatus != 0 || phkResult == NULL) {
            *pstatus = -1;
            return pstatus;
        }
        this->key = phkResult;
    }
    *pstatus = 0;
    return pstatus;
}

void dk2::RegKey::close() {
    if (patch::registry_to_config::enabled) {
        if (this->key) patch::registry_to_config::close((Reg2Cfg *) this->key);
        this->key = NULL;
        return;
    }
    if ( !this->key || !RegCloseKey(this->key) ) this->key = NULL;
}

int *dk2::RegKey::create_key(int *pstatus, LPCSTR lpSubKey, RegKey *a4_pHkey) {
    if (patch::registry_to_config::enabled) {
        HKEY result = (HKEY) patch::registry_to_config::createSubCfg((Reg2Cfg *) this->key, lpSubKey);
        if (result) {
            if (a4_pHkey->key) patch::registry_to_config::close((Reg2Cfg *) a4_pHkey->key);
            a4_pHkey->key = result;
        }
        *pstatus = a4_pHkey->key ? 0 : -1;
        return pstatus;
    }
    HKEY phkResult;
    LSTATUS lstatus = RegCreateKeyExA(this->key, lpSubKey, 0, NULL, 0, 0xF003Fu, NULL, &phkResult, NULL);
    if (lstatus == 0 || phkResult == NULL) {
        *pstatus = -1;
        return pstatus;
    }
    if (a4_pHkey->key && RegCloseKey(a4_pHkey->key)) {
        RegCloseKey(phkResult);
        *pstatus = -1;
        return pstatus;
    }
    a4_pHkey->key = phkResult;
    *pstatus = 0;
    return pstatus;
}


int *dk2::RegKey::open_key(int *pstatus, LPCSTR lpSubKey, RegKey *a4_key) {
    if (patch::registry_to_config::enabled) {
        HKEY result = (HKEY) patch::registry_to_config::openSubCfg((Reg2Cfg *) this->key, lpSubKey);
        if (result) {
            if (a4_key->key) patch::registry_to_config::close((Reg2Cfg *) a4_key->key);
            a4_key->key = result;
        }
        *pstatus = a4_key->key ? 0 : -1;
        return pstatus;
    }
    HKEY phkResult;
    LSTATUS lstatus = RegOpenKeyExA(this->key, lpSubKey, 0, 0xF003Fu, &phkResult);
    if (lstatus != 0 && phkResult == NULL) {
        *pstatus = -1;
        return pstatus;
    }
    if ( a4_key->key && RegCloseKey(a4_key->key)) {
        RegCloseKey(phkResult);
        *pstatus = -1;
        return pstatus;
    }
    a4_key->key = phkResult;
    *pstatus = 0;
    return pstatus;
}


int *dk2::RegKey::write_bytes(
        int *pstatus,
        LPCSTR lpValueName,
        uint32_t dwType,
        BYTE *lpData,
        uint32_t cbData) {
    if (patch::registry_to_config::enabled) {
        switch (dwType) {
        case REG_BINARY: break;
        case REG_FULL_RESOURCE_DESCRIPTOR: break;
            default: {
                printf("[err] invalid bytes type %d\n", dwType);
                *pstatus = -1;
                return pstatus;
            } break;
        }
        bool status = patch::registry_to_config::writeBytes((Reg2Cfg *) this->key, lpValueName, lpData, cbData);
        *pstatus = status ? 0 : -1;
        return pstatus;
    }
    if (!lpData || !this->key || !(lpValueName || dwType == 1)) {
        *pstatus = -1;
        return pstatus;
    }
    patch::use_wasd_by_default_patch::useAlternativeName(lpValueName);
    if (RegSetValueExA(this->key, lpValueName, 0, dwType, lpData, cbData) != 0) {
        *pstatus = -1;
        return pstatus;
    }
    *pstatus = 0;
    return pstatus;
}


unsigned int dk2::RegKey::read_Bytes_size(LPCSTR lpValueName) {
    if ( !lpValueName || !this->key ) return 0;
    if (patch::registry_to_config::enabled) {
        return patch::registry_to_config::readBytesSize((Reg2Cfg *) this->key, lpValueName);
    }
    patch::use_wasd_by_default_patch::useAlternativeName(lpValueName);
    LSTATUS Value = RegQueryValueExA(this->key, lpValueName, NULL, NULL, NULL, (LPDWORD) &lpValueName);
    return Value == 0 ? (unsigned int)lpValueName : 0;
}

int *dk2::RegKey::read_Bytes(int *pstatus, LPCSTR lpValueName, LPBYTE lpData, uint32_t cbData) {
    if (!lpValueName || this->key == NULL) {
        printf("[err] tried to read \"%s\" but key is NULL\n", lpValueName);
        *pstatus = -1;
        return pstatus;
    }
    if (patch::registry_to_config::enabled) {
        bool status = patch::registry_to_config::readBytes((Reg2Cfg *) this->key, lpValueName, lpData, cbData);
        *pstatus = status ? 0 : -1;
        return pstatus;
    }
    patch::use_wasd_by_default_patch::useAlternativeName(lpValueName);
    DWORD type = 0;
    if (RegQueryValueExA(this->key, lpValueName, 0, &type, lpData, (LPDWORD) &cbData) != 0) {
        *pstatus = -1;
        return pstatus;
    }
    *pstatus = 0;
    return pstatus;
}

int *dk2::RegKey::write_DWORD(int *pstatus, LPCSTR lpValueName, uint32_t Data) {
    if (!Data || !this->key || !lpValueName) {
        *pstatus = -1;
        return pstatus;
    }
    if (patch::registry_to_config::enabled) {
        bool status = patch::registry_to_config::writeInt((Reg2Cfg *) this->key, lpValueName, Data);
        *pstatus = status ? 0 : -1;
        return pstatus;
    }
    if (RegSetValueExA(this->key, lpValueName, 0, 4u, (const BYTE *) &Data, 4u) != 0) {
        *pstatus = -1;
        return pstatus;
    }
    *pstatus = 0;
    return pstatus;
}

int *dk2::RegKey::read_DWORD(int *pstatus, LPCSTR lpValueName, uint32_t *pValue) {
    if(gog::RegistryConfig_patch::isEnabled()) {
        if (gog::cfg::patchRegistryConfig(pstatus, lpValueName, (DWORD *) pValue) != -1) return pstatus;
    }
    if (!lpValueName || this->key == NULL) {
        *pstatus = -1;
        return pstatus;
    }
    if (patch::registry_to_config::enabled) {
        bool status = patch::registry_to_config::readInt((Reg2Cfg *) this->key, lpValueName, *(int *) pValue);
        *pstatus = status ? 0 : -1;
        return pstatus;
    }
    DWORD Type = 0;
    DWORD value;
    DWORD cbData = sizeof(value);
    if(RegQueryValueExA(this->key, lpValueName, NULL, &Type, (LPBYTE) &value, &cbData) != ERROR_SUCCESS) {
        *pstatus = -1;
        return pstatus;
    }
    if (RegQueryValueExA(this->key, lpValueName, NULL, &Type, NULL, NULL) != ERROR_SUCCESS) {
        HKEY tmp;
        int status;
        if (RegOpenKeyA(this->key, lpValueName, &tmp)) {
            status = -1;
        } else {
            RegCloseKey(tmp);
            status = -2;
        }
        *pstatus = -1;
        return pstatus;
    }
    signed int v8_type = Type;
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

int *dk2::RegKey::write_GUID(int *pstatus, LPCSTR lpValueName, GUID *guid) {
    if (patch::registry_to_config::enabled) {
        bool status = patch::registry_to_config::writeGuid((Reg2Cfg *) this->key, lpValueName, guid);
        *pstatus = status ? 0 : -1;
        return pstatus;
    }

    sprintf(
      g_tmpWriteGuidStr,
      "{%.8X-%.4X-%.4X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X%}",
      guid->Data1,
      guid->Data2,
      guid->Data3,
      guid->Data4[0],
      guid->Data4[1],
      guid->Data4[2],
      guid->Data4[3],
      guid->Data4[4],
      guid->Data4[5],
      guid->Data4[6],
      guid->Data4[7]);
    if ( !g_tmpWriteGuidStr || !this->key ) {
        *pstatus = -1;
        return pstatus;
    }
    if (RegSetValueExA(this->key, lpValueName, 0, 1u, (const BYTE *) g_tmpWriteGuidStr, strlen(g_tmpWriteGuidStr)) != 0) {
        *pstatus = -1;
        return pstatus;
    }
    *pstatus = 0;
    return pstatus;
}

void scanfGuid(const char *str, GUID *a4_guid) {
    GUID *v9_guid = a4_guid;
    uint16_t a4;
    uint16_t a5;
    uint32_t a6;
    sscanf(
        str,
        "{%lx-%hx-%hx-%hx-%4hx%8lx}",
        &a4_guid->Data1,
        &a4_guid->Data2,
        &a4_guid->Data3,
        &a4,
        &a5,
        &a6);
    *(WORD *) &v9_guid->Data4[0] = _byteswap_ushort(a4);
    *(WORD *) &v9_guid->Data4[2] = _byteswap_ushort(a5);
    *(DWORD *) &v9_guid->Data4[4] = _byteswap_ulong(a6);
}

int *dk2::RegKey::read_GUID(int *pstatus, LPCSTR lpValueName, GUID *a4_guid) {
    if (patch::registry_to_config::enabled) {
        bool status = patch::registry_to_config::readGuid((Reg2Cfg *) this->key, lpValueName, a4_guid);
        *pstatus = status ? 0 : -1;
        return pstatus;
    }
    const CHAR *v4_name = lpValueName;
    DWORD type;
    if ( RegQueryValueExA(this->key, lpValueName, NULL, &type, NULL, NULL) != 0 ) {
        HKEY phkResult;
        int status;
        if ( RegOpenKeyA(this->key, v4_name, &phkResult) != 0 ) {
            status = -1;
        } else {
            RegCloseKey(phkResult);
            status = -2;
        }
        *pstatus = -1;
        return pstatus;
    }
    if (type != 1) {
        *pstatus = -1;
        return pstatus;
    }
    if (!v4_name) {
        scanfGuid(g_tmpReadGuidStr, a4_guid);
        *pstatus = 0;
        return pstatus;
    }
    if (!this->key) {
        *pstatus = -1;
        return pstatus;
    }
    DWORD size;
    LSTATUS lstatus = RegQueryValueExA(this->key, v4_name, NULL, NULL, NULL, &size);
    if (lstatus != 0 || size != 39) {
        *pstatus = -1;
        return pstatus;
    }
    int status;
    if (*this->read_String(&status, v4_name, g_tmpReadGuidStr, 40, NULL) < 0) {
        *pstatus = -1;
        return pstatus;
    }
    scanfGuid(g_tmpReadGuidStr, a4_guid);
    *pstatus = 0;
    return pstatus;
}

void writeDefault(char *outBuf, char *defaultVal, int bufSize) {
    if ( defaultVal ) {
        if ( bufSize ) {
            strncpy(outBuf, defaultVal, bufSize);
        } else {
            strcpy(outBuf, defaultVal);
        }
    }
}


int *dk2::RegKey::write_String(int *pstatus, LPCSTR lpValueName, const char *lpData) {
    if ( !lpData || !this->key ) {
        *pstatus = -1;
        return pstatus;
    }
    if (patch::registry_to_config::enabled) {
        bool status = patch::registry_to_config::writeString((Reg2Cfg *) this->key, lpValueName, lpData);
        *pstatus = status ? 0 : -1;
        return pstatus;
    }
    if (RegSetValueExA(this->key, lpValueName, 0, 1u, (const BYTE *) lpData, strlen(lpData)) != 0) {
        *pstatus = -1;
        return pstatus;
    }
    *pstatus = 0;
    return pstatus;
}

int *dk2::RegKey::read_String(
        int *pstatus,
        LPCSTR lpValueName,
        char *outBuf,
        int bufSize,
        char *defaultVal) {
    if (patch::registry_to_config::enabled) {
        bool status = patch::registry_to_config::readString((Reg2Cfg *) this->key, lpValueName, outBuf, bufSize);
        if (!status) {
            writeDefault(outBuf, defaultVal, bufSize);
        }
        *pstatus = status ? 0 : -1;
        return pstatus;
    }
    DWORD readSize = bufSize;
    if (readSize == 0) {
        if ( lpValueName && this->key ) {
            DWORD size;
            if (RegQueryValueExA(this->key, lpValueName, NULL, NULL, NULL, &size) == 0) {
                readSize = size;
            }
        }
    }
    DWORD type;
    if (RegQueryValueExA(this->key, lpValueName, NULL, &type, NULL, NULL) != 0) {
        HKEY phkResult;
        int status;
        if ( RegOpenKeyA(this->key, lpValueName, &phkResult) ) {
            status = -1;
        } else {
            RegCloseKey(phkResult);
            status = -2;
        }
        writeDefault(outBuf, defaultVal, bufSize);
        *pstatus = -1;
        return pstatus;
    }
    int v10_ty = type;
    if (v10_ty != 1 && v10_ty != 2) {
        writeDefault(outBuf, defaultVal, bufSize);
        *pstatus = -1;
        return pstatus;
    }
    HKEY f0_key;
    if ( !lpValueName || (f0_key = this->key) == NULL ) {
        writeDefault(outBuf, defaultVal, bufSize);
        *pstatus = -1;
        return pstatus;
    }
    DWORD ignType = 0;
    DWORD size = readSize;
    if (RegQueryValueExA(f0_key, lpValueName, NULL, &ignType, (LPBYTE) outBuf, &size) != 0) {
        writeDefault(outBuf, defaultVal, bufSize);
        *pstatus = -1;
        return pstatus;
    }
    *pstatus = 0;
    return pstatus;
}



