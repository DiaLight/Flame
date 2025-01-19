//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_GOG_GLOBALS_H
#define EMBER_GOG_GLOBALS_H

#include <Windows.h>
#include <ddraw.h>
#include <d3d.h>

namespace gog {
    extern bool g_isAntialiasGt10;
    extern bool g_isRendererPaused;
    extern bool g_isColorFill;
    extern bool g_isSmth_noRef;
    extern bool g_isSceneDrawing;
    extern bool g_isFlip;
    extern bool g_isMsgSent;
    extern HWND g_hWnd;
    extern DWORD g_dwWidth;
    extern DWORD g_dwHeight;
    extern RECT g_renderRect;

    namespace orig {
        extern IDirectDraw4 *pIDirectDraw4;
        extern IDirect3D3 *pIDirect3D3;
        extern IDirect3DDevice3 *pIDirect3DDevice3;
        extern IDirectDrawSurface4 *pIDirectDrawSurface4_last;
        extern IDirectDrawSurface4 *pIDirectDrawSurface4_zbuf;
        extern IDirectDrawSurface4 *pIDirectDrawSurface4_640x480;
        extern IDirectDrawSurface4 *pIDirectDrawSurface4_coop;
        extern IDirect3DViewport3 *pIDirect3DViewport3;
    }

}

#endif //EMBER_GOG_GLOBALS_H
