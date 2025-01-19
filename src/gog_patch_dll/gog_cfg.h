//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_GOG_CFG_H
#define EMBER_GOG_CFG_H

#include <Windows.h>

namespace gog::cfg {

    extern bool iDisableDEP;
    extern DWORD iScaleMode;
    extern bool iBumpmap;
    extern bool iNotOnTop;
    extern bool iAnisotropy;
    extern bool iHighRes;
    extern DWORD iAntialias;
    extern DWORD iVwait;
    extern DWORD iCpuIdle;
    extern bool iExtraAntialias;
    extern bool iRealFullscreen;
    extern bool iDisableFourCC;
    extern bool iSingleCore;
    extern DWORD iRestoreMode;

    void load();

    int patchRegistryConfig(int *status, LPCSTR lpValueName, DWORD *pValue);

}

#endif //EMBER_GOG_CFG_H
