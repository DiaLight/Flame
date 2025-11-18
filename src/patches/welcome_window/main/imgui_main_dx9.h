//
// Created by DiaLight on 11/8/2025.
//

#ifndef FLAME_IMGUI_MAIN_DX9_H
#define FLAME_IMGUI_MAIN_DX9_H

#include <d3d9.h>

namespace patch::welcome_window {
    extern LPDIRECT3D9 g_pD3D;
    extern LPDIRECT3DDEVICE9 g_pd3dDevice;
    extern bool g_DeviceLost;
    extern UINT g_ResizeWidth, g_ResizeHeight;
    extern D3DPRESENT_PARAMETERS g_d3dpp;
}

#endif // FLAME_IMGUI_MAIN_DX9_H
