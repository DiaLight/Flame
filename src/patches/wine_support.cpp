//
// Created by DiaLight on 10/7/2025.
//

#include "wine_support.h"
#include <Windows.h>
#include "logging.h"
#include <string>


struct RegKeyCxx {
    HKEY hKey = NULL;

    RegKeyCxx() = default;
    ~RegKeyCxx() {
        clear();
    }
    RegKeyCxx(RegKeyCxx&& v)  noexcept : hKey(v.hKey) { v.hKey = NULL; }
    RegKeyCxx& operator=(RegKeyCxx&& v)  noexcept { hKey = v.hKey; v.hKey = NULL; return *this; }
    RegKeyCxx(const RegKeyCxx&)            = delete;
    RegKeyCxx& operator=(const RegKeyCxx&) = delete;

    void clear() {
        if(hKey) {
            RegCloseKey(hKey);
            hKey = NULL;
        }
    }
    
    explicit operator bool() const { return hKey != NULL; }
    
    bool _open(HKEY hParentKey, LPCSTR lpSubKey) {
        clear();
        LSTATUS status = RegOpenKeyExA(hParentKey, lpSubKey, 0, KEY_READ, &this->hKey);
        if(status == ERROR_SUCCESS) return true;
        if(status == ERROR_FILE_NOT_FOUND) return false;
        patch::log::dbg("RegOpenKeyExA failed: %08X\n", status);
        return false;
    }
    bool _create(HKEY hParentKey, LPCSTR lpSubKey) {
        clear();
        // will open existing or create a new one
        LSTATUS status = RegCreateKeyA(hParentKey, lpSubKey, &this->hKey);
        if(status == ERROR_SUCCESS) return true;
        patch::log::dbg("RegCreateKeyA failed: %08X\n", status);
        return false;
    }

    bool open_hkcu(LPCSTR lpSubKey) { return _open(HKEY_CURRENT_USER, lpSubKey); }
    
    [[nodiscard]] RegKeyCxx open_subkey(LPCSTR lpSubKey) const {
        RegKeyCxx sub;
        sub._open(this->hKey, lpSubKey);
        return sub;
    }
    [[nodiscard]] RegKeyCxx open_subkey(const std::string &subKey) const {
        return open_subkey(subKey.c_str());
    }
    [[nodiscard]] RegKeyCxx create_subkey(LPCSTR lpSubKey) const {
        RegKeyCxx sub;
        sub._create(this->hKey, lpSubKey);
        return sub;
    }
    [[nodiscard]] RegKeyCxx create_subkey(const std::string &subKey) const {
        return create_subkey(subKey.c_str());
    }

    [[nodiscard]] std::string get_str(LPCSTR lpValueName) const {
        DWORD type = REG_SZ;
        DWORD size = 0;
        LSTATUS status;
        status = RegQueryValueExA(this->hKey, lpValueName, NULL, &type, NULL, &size);
        if (status != ERROR_SUCCESS) {
            patch::log::dbg("%s value is absent", lpValueName);
            return "";
        }
        if (type != REG_SZ) {
            patch::log::dbg("%s value has invalid type", lpValueName);
            return "";
        }
        std::string str;
        str.resize(size);
        status = RegQueryValueExA(this->hKey, lpValueName, NULL, NULL, reinterpret_cast<LPBYTE>(str.data()), &size);
        if (status != ERROR_SUCCESS) {
            patch::log::dbg("unable to read %s value", lpValueName);
            return "";
        }
        return str;
    }
    
    [[nodiscard]] bool set_str(LPCSTR lpValueName, const std::string &value) const {
        LSTATUS status = RegSetValueExA(
            this->hKey, lpValueName,
            NULL, REG_SZ,
            (const BYTE*) value.c_str(), value.length() + 1
        );
        if (status != ERROR_SUCCESS) {
            patch::log::dbg("unable to create %s value", lpValueName);
            return false;
        }
        return true;
    }
    
};


std::string get_ModuleName() {
    CHAR fileName[MAX_PATH];
//    DWORD len = GetModuleBaseNameA(NULL, NULL, fileName, sizeof(fileName));
    DWORD len = GetModuleFileNameA(NULL, fileName, sizeof(fileName));
    if(!len) return "";
    fileName[len] = '\0';
    for(CHAR *p = &fileName[len - 1]; p >= fileName; p--) {
        CHAR ch = *p;
        if(ch == '\\' || ch == '/') return p + 1;
    }
    return fileName;
}

void patch::wine_support::init() {
    RegKeyCxx wine;
    if(!wine.open_hkcu("SOFTWARE\\Wine")) return;
    patch::log::dbg("Wine detected!");

    std::string foundVmem;
    if(RegKeyCxx d3d = wine.open_subkey("Direct3D")) {
        if(std::string vmem = d3d.get_str("VideoMemorySize"); !vmem.empty()) {
            patch::log::dbg("found Wine\\Direct3D.VideoMemorySize: %s MB", vmem.c_str());
            foundVmem = vmem;
        }
    }
    std::string modName = get_ModuleName();
    if(RegKeyCxx appDefs = wine.open_subkey("AppDefaults")) {
        if(RegKeyCxx mod = appDefs.open_subkey(modName)) {
            if(RegKeyCxx d3d = mod.open_subkey("Direct3D")) {
                if(std::string vmem = d3d.get_str("VideoMemorySize"); !vmem.empty()) {
                    patch::log::dbg("found Wine\\AppDefaults\\%s\\Direct3D.VideoMemorySize: %s MB", modName.c_str(), vmem.c_str());
                    foundVmem = vmem;
                }
            }
        }
    }
    if(!foundVmem.empty()) return;
    {
        char msg[1024];
        snprintf(
            msg, sizeof(msg),
            "Detected Wine, but Wine\\AppDefaults\\%s\\Direct3D.VideoMemorySize is not configured\n"
            "Allow Flame to configure Wine?", modName.c_str());
        int res = MessageBoxA(NULL, msg, "Flame", MB_YESNO);
        if(res != IDYES) {
            patch::log::dbg("skipping wine configuration");
            return;
        }
    }
    if(RegKeyCxx appDefs = wine.create_subkey("AppDefaults")) {
        if(RegKeyCxx mod = appDefs.create_subkey(modName)) {
            if(RegKeyCxx d3d = mod.create_subkey("Direct3D")) {
                if(d3d.set_str("VideoMemorySize", "2048")) {
                    patch::log::dbg("Wine registry has been patched!");
                    MessageBoxA(NULL, "Direct3D.VideoMemorySize has been configured!\nPlease restart the game!", "Flame", MB_OK);
                    ExitProcess(0);
                }
            }
        }
    }
    MessageBoxA(NULL, "Failed to configure Wine", "Flame", MB_OK);
}
