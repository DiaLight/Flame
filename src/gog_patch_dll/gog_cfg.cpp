//
// Created by DiaLight on 20.01.2023.
//
#include <gog_cfg.h>
#include <gog_globals.h>
#include <ShlObj_core.h>
#include <gog_debug.h>
#include <tools/flame_config.h>

using namespace gog;

bool cfg::iDisableDEP;
DWORD cfg::iScaleMode;
bool cfg::iBumpmap;
bool cfg::iNotOnTop;
bool cfg::iAnisotropy;
bool cfg::iHighRes;
DWORD cfg::iAntialias;
DWORD cfg::iVwait;
DWORD cfg::iCpuIdle;
bool cfg::iExtraAntialias;
bool cfg::iRealFullscreen;
bool cfg::iDisableFourCC;
bool cfg::iSingleCore;
DWORD cfg::iRestoreMode;


namespace patch::replace_parse_command_line {
    extern bool enabled;
    bool parse();
}

extern flame_config::define_flame_option<bool> o_dk2_enableBumpMapping;
extern flame_config::define_flame_option<bool> o_dk2_enableBumpLuminance;

flame_config::define_flame_option<int> o_gog_Video_antialias(
    "gog:video:antialias", flame_config::OG_Config,
    "",
    11
);

flame_config::define_flame_option<bool> o_gog_Video_ExtraAntialias(
     "gog:video:ExtraAntialias", flame_config::OG_Config,
     "",
     false
);
flame_config::define_flame_option<bool> o_gog_Video_HighRes(
     "gog:video:HighRes", flame_config::OG_Config,
     "",
     false
);
flame_config::define_flame_option<bool> o_gog_Video_Anisotropy(
     "gog:video:Anisotropy", flame_config::OG_Config,
     "",
     false
);
flame_config::define_flame_option<int> o_gog_Video_Vwait(
     "gog:video:Vwait", flame_config::OG_Config,
     "",
     1
);
flame_config::define_flame_option<int> o_gog_Video_ScaleMode(
     "gog:video:ScaleMode", flame_config::OG_Config,
     "",
     1
);
flame_config::define_flame_option<bool> o_gog_Video_DisableFourCC(
     "gog:video:DisableFourCC", flame_config::OG_Config,
     "",
     false
);
flame_config::define_flame_option<bool> o_gog_Video_Bumpmap(
     "gog:video:Bumpmap", flame_config::OG_Config,
     "",
     false
);
flame_config::define_flame_option<bool> o_gog_Video_RealFullscreen(
     "gog:video:RealFullscreen", flame_config::OG_Config,
     "",
     true
);
flame_config::define_flame_option<int> o_gog_Misc_CpuIdle(
     "gog:misc:CpuIdle", flame_config::OG_Config,
     "",
     0
);
flame_config::define_flame_option<bool> o_gog_Misc_SingleCore(
     "gog:misc:SingleCore", flame_config::OG_Config,
     "",
     true
);
flame_config::define_flame_option<bool> o_gog_Misc_DisableDEP(
     "gog:misc:DisableDEP", flame_config::OG_Config,
     "",
     true
);
flame_config::define_flame_option<int> o_gog_Misc_RestoreMode(
     "gog:misc:RestoreMode", flame_config::OG_Config,
     "",
     0
);
flame_config::define_flame_option<bool> o_gog_Misc_NotOnTop(
     "gog:misc:NotOnTop", flame_config::OG_Config,
     "",
     false
);


namespace patch::replace_gog_config {
    bool enabled = true;

    void cfg_load_flame() {
        cfg::iAntialias = *o_gog_Video_antialias;
        cfg::iExtraAntialias = *o_gog_Video_ExtraAntialias;
        cfg::iHighRes = *o_gog_Video_HighRes;
        cfg::iAnisotropy = *o_gog_Video_Anisotropy;
        cfg::iVwait = *o_gog_Video_Vwait;
        cfg::iScaleMode = *o_gog_Video_ScaleMode;
        cfg::iDisableFourCC = *o_gog_Video_DisableFourCC;
        cfg::iBumpmap = *o_gog_Video_Bumpmap;
        cfg::iRealFullscreen = *o_gog_Video_RealFullscreen;
        cfg::iCpuIdle = *o_gog_Misc_CpuIdle;
        cfg::iSingleCore = *o_gog_Misc_SingleCore;
        cfg::iDisableDEP = *o_gog_Misc_DisableDEP;
        cfg::iRestoreMode = *o_gog_Misc_RestoreMode;
        cfg::iNotOnTop = *o_gog_Misc_NotOnTop;
    }
}

void cfg_load_original() {
    WCHAR appdataDir[512];
    SHGetFolderPathW(NULL, CSIDL_APPDATA, NULL, 0, appdataDir);
    wcscat_s(appdataDir, ARRAYSIZE(appdataDir), L"\\GOG\\DungeonKeeper2\\Config.ini");
    cfg::iAntialias = GetPrivateProfileIntW(L"Video", L"Antialias", 11, appdataDir);
    cfg::iExtraAntialias = GetPrivateProfileIntW(L"Video", L"ExtraAntialias", 0, appdataDir) != 0;
    cfg::iHighRes = GetPrivateProfileIntW(L"Video", L"HighRes", 0, appdataDir) != 0;
    cfg::iAnisotropy = GetPrivateProfileIntW(L"Video", L"Anisotropy", 0, appdataDir) != 0;
    cfg::iVwait = GetPrivateProfileIntW(L"Video", L"Vwait", 1, appdataDir);
    cfg::iScaleMode = GetPrivateProfileIntW(L"Video", L"ScaleMode", 1, appdataDir);
    cfg::iDisableFourCC = GetPrivateProfileIntW(L"Video", L"DisableFourCC", 0, appdataDir) != 0;
    cfg::iBumpmap = GetPrivateProfileIntW(L"Video", L"Bumpmap", 0, appdataDir) != 0;
    cfg::iRealFullscreen = GetPrivateProfileIntW(L"Video", L"RealFullscreen", 1, appdataDir) != 0;
    cfg::iCpuIdle = GetPrivateProfileIntW(L"Misc", L"CpuIdle", 0, appdataDir);
    cfg::iSingleCore = GetPrivateProfileIntW(L"Misc", L"SingleCore", 1, appdataDir) != 0;
    cfg::iDisableDEP = GetPrivateProfileIntW(L"Misc", L"DisableDEP", 1, appdataDir) != 0;
    cfg::iRestoreMode = GetPrivateProfileIntW(L"Misc", L"RestoreMode", 0, appdataDir);
    cfg::iNotOnTop = GetPrivateProfileIntW(L"Misc", L"NotOnTop", 0, appdataDir) != 0;
}

void cfg::load() {
    if (patch::replace_gog_config::enabled) {
        patch::replace_gog_config::cfg_load_flame();
    } else {
        cfg_load_original();
    }
    if (cfg::iAntialias > 10) {
        cfg::iAntialias -= 10;
        gog::g_isAntialiasGt10 = true;
    }
    OSVERSIONINFOA VersionInformation;
    if (cfg::iRealFullscreen) {
        cfg::iRestoreMode = 2;
    } else if (cfg::iRestoreMode == 0) {
        memset(&VersionInformation, 0, sizeof(VersionInformation));
        VersionInformation.dwOSVersionInfoSize = sizeof(VersionInformation);
        GetVersionExA(&VersionInformation);
        if (VersionInformation.dwMajorVersion < 6) {
            cfg::iRestoreMode = 2;
        } else {
            cfg::iRestoreMode = 1;
            if (IsDebuggerPresent()) {
                cfg::iRestoreMode = 2;
            }
        }
    }
    if (!cfg::iBumpmap) {
        if (patch::replace_parse_command_line::enabled) {
            if (*o_dk2_enableBumpLuminance || *o_dk2_enableBumpMapping) {
                cfg::iBumpmap = true;
            }
        } else {
            char Destination[512];
            LPSTR CommandLineA = GetCommandLineA();
            strcpy_s(Destination, ARRAYSIZE(Destination), CommandLineA);
            _strlwr_s(Destination, ARRAYSIZE(Destination));
            if (strstr(CommandLineA, "enablebumpluminance") != nullptr ||
                strstr(CommandLineA, "enablebumpmapping") != nullptr) {
                cfg::iBumpmap = true;
            }
        }
    }
}

int cfg::patchRegistryConfig(int *status, LPCSTR lpValueName, DWORD *pValue) {
    if (strcmp(lpValueName, "Screen Depth") == 0) {
        *status = 0;
        *pValue = 32;
        return 0;
    }
    if (strcmp(lpValueName, "Screen Hardware3D") == 0) {
        *status = 0;
        *pValue = 1;
        return 0;
    }
    if (strcmp(lpValueName, "Screen Mode Type") == 0) {
        *status = 0;
        *pValue = 3;
        return 0;
    }
    if (strcmp(lpValueName, "Engine Id") == 0) {
        *status = 0;
        *pValue = 2;
        return 0;
    }
    if (strcmp(lpValueName, "Res 1024*768 Enabled") == 0) {
        *status = 0;
        *pValue = 1;
        return 0;
    }
    if (strcmp(lpValueName, "Res 1280*1024 Enable") == 0) {
        *status = 0;
        *pValue = 1;
        return 0;
    }
    if (strcmp(lpValueName, "Res 1600*1200 Enable") == 0) {
        *status = 0;
        *pValue = 1;
        return 0;
    }
    if (strcmp(lpValueName, "Screen Windowed") == 0) {
        *status = 0;
        *pValue = 0;
        return 0;
    }
    if (strcmp(lpValueName, "Cheap Lighting") == 0) {
        *status = 0;
        *pValue = 0;
        return 0;
    }
    if (strcmp(lpValueName, "Engine Id") == 0) {
        *status = 0;
        *pValue = 2;
        return 0;
    }
    if (strcmp(lpValueName, "EnvironmentMapping") == 0) {
        *status = 0;
        *pValue = 1;
        return 0;
    }
    if (strcmp(lpValueName, "High Res Textures") == 0) {
        *status = 0;
        *pValue = 1;
        return 0;
    }
    if (strcmp(lpValueName, "Machine Spec Level") == 0) {
        *status = 0;
        *pValue = 10;
        return 0;
    }
    if (strcmp(lpValueName, "PMesh Reduction Level") == 0) {
        *status = 0;
        *pValue = 0;
        return 0;
    }
    return -1;
}
