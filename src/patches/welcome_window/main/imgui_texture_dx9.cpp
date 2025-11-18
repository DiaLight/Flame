//
// Created by DiaLight on 11/8/2025.
//

#include <d3d9.h>
#include <d3dx9tex.h>
#include "../welcome_window_imgui.h"
#include "imgui_main_dx9.h"


ImTextureID patch::welcome_window::LoadTextureFromBuffer(void* data, size_t size, SIZE& texSize) {
    PDIRECT3DTEXTURE9 texture;
    HRESULT hr = D3DXCreateTextureFromFileInMemory(g_pd3dDevice, data, size, &texture);
    if (hr != S_OK)
        return ImTextureID_Invalid;
    // Retrieve description of the texture surface so we can access its size
    D3DSURFACE_DESC my_image_desc;
    texture->GetLevelDesc(0, &my_image_desc);

    texSize.cx = (int)my_image_desc.Width;
    texSize.cy = (int)my_image_desc.Height;

    return (ImTextureID)(intptr_t)texture;
}

