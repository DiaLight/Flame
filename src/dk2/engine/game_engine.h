//
// Created by DiaLight on 12/10/2025.
//

#ifndef FLAME_GAME_ENGINE_H
#define FLAME_GAME_ENGINE_H

#include <ddraw.h>
#include <dk2/MyDdSurfaceEx.h>
#include "dk2/Obj79D1C0.h"

namespace dk2 {

    void setHInstance(HINSTANCE hInst);
    HINSTANCE getHInstance();

    extern char g_bullfrogClassName[260];

    void setWindowName(int *pstatus, const char *name);
    char *getWindowName();

    int *setLibIconName(int *pstatus, __int16 a2);
    LPCSTR getLibIconName();

    typedef LRESULT (*CustomDefWindowProcA_t)(HWND, UINT, WPARAM, LPARAM);
    void setCustomDefWindowProcA(CustomDefWindowProcA_t proc);
    CustomDefWindowProcA_t getCustomDefWindowProcA();

    void setHWindow(HWND hWnd);
//    HWND getHWindow();

    extern HWND g_hWnd;

    extern HWND g_hBullfrogWindow;
    void BullfrogWindow_registerClass();

    extern GUID *g_selectedDDGuid;
    void setSelectedDDGuid(GUID *guid);

    extern LPDIRECTDRAW ge_lpSurfaceDD;
    void setSurfaceDD(LPDIRECTDRAW lpdd);

    extern MyDdSurfaceEx g_offScreen;
    extern MyDdSurfaceEx *g_pCurOffScreen;
    void setCurOffScreen(MyDdSurfaceEx *surf);

    extern MyDdSurfaceEx g_primarySurf;
    extern LPDIRECTDRAWPALETTE g_lpDDPalette;
    extern LPDIRECTDRAWCLIPPER g_lpDDClipper;

    extern Obj79D1C0 Obj79D1C0_instance;

}

namespace dk2 {

    int *ge_dk2dd_init(
        int *pstatus, uint32_t width, uint32_t height,
        uint32_t displayBitness, int initFlags, LPPALETTEENTRY entries_);

    extern LPDIRECTDRAW g_dk2dd;

    int *__cdecl ge_createDirectDrawObject(int *pstatus, GUID *lpGUID, LPDIRECTDRAW *lplpDD);

    void ge_ddReleaseSurfaces();
    void ge_dk2dd_destroy();

}

#endif // FLAME_GAME_ENGINE_H
