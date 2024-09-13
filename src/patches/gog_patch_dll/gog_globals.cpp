//
// Created by DiaLight on 20.01.2023.
//
#include <gog_globals.h>

bool gog::g_isAntialiasGt10 = false;
bool gog::g_isRendererPaused = false;
bool gog::g_isColorFill = false;
bool gog::g_isSmth_noRef = false;
bool gog::g_isSceneDrawing = false;
bool gog::g_isFlip = false;
bool gog::g_isMsgSent = false;
HWND gog::g_hWnd = nullptr;
DWORD gog::g_dwWidth = 0;
DWORD gog::g_dwHeight = 0;
RECT gog::g_renderRect = {0};


IDirectDraw4 *gog::orig::pIDirectDraw4 = nullptr;
IDirect3D3 *gog::orig::pIDirect3D3 = nullptr;
IDirect3DDevice3 *gog::orig::pIDirect3DDevice3 = nullptr;
IDirectDrawSurface4 *gog::orig::pIDirectDrawSurface4_last = nullptr;
IDirectDrawSurface4 *gog::orig::pIDirectDrawSurface4_zbuf = nullptr;
IDirectDrawSurface4 *gog::orig::pIDirectDrawSurface4_640x480 = nullptr;
IDirectDrawSurface4 *gog::orig::pIDirectDrawSurface4_coop = nullptr;
IDirect3DViewport3 *gog::orig::pIDirect3DViewport3 = nullptr;
