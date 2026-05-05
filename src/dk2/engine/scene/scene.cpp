//
// Created by DiaLight on 1/22/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/MyCESurfHandle.h"
#include "patches/big_resolution_fix/big_resolution_fix.h"
#include "patches/logging.h"

int dk2::configureFlagsAndTexturesCount() {
    DDCAPS caps;
    memset(&caps, 0, sizeof(caps));
    static_assert(sizeof(DDCAPS) == 380);
    caps.dwSize = sizeof(DDCAPS);
    MyDirectDraw_instance.dd4->GetCaps(&caps, NULL);
    if ((caps.dwCaps2 & 0x20000) == 0)
        MyDirectDraw_instance.flags &= ~2u;
    if ((MyDirectDraw_instance.flags & 1) != 0) {
        MyDirectDraw_instance.flags &= ~0x10u;
        MyDirectDraw_instance.texturesCount = 1;
        return 1;
    }
    D3DDEVICEDESC helDesc;
    static_assert(sizeof(helDesc) == 252);
    memset(&helDesc, 0, sizeof(helDesc));
    helDesc.dwSize = sizeof(helDesc);

    D3DDEVICEDESC devDriverDesc;
    static_assert(sizeof(devDriverDesc) == 252);
    memset(&devDriverDesc, 0, sizeof(devDriverDesc));
    devDriverDesc.dwSize = sizeof(devDriverDesc);

    devDriverDesc.dwFlags |= 0x42u;
    devDriverDesc.dpcTriCaps.dwSize = 56;
    MyDirectDraw_instance.d3d3_halDevice->GetCaps(&devDriverDesc, &helDesc);
    if ((devDriverDesc.dwDevCaps & 0x400) == 0) return 0;
    if ((devDriverDesc.dpcTriCaps.dwSrcBlendCaps & 0x10) == 0) return 0;
    if ((devDriverDesc.dpcTriCaps.dwSrcBlendCaps & 2) == 0) return 0;
    if ((devDriverDesc.dpcTriCaps.dwDestBlendCaps & 0x20) == 0) return 0;
    if ((devDriverDesc.dpcTriCaps.dwDestBlendCaps & 2) == 0) return 0;
    if ((devDriverDesc.dpcTriCaps.dwZCmpCaps & 8) == 0) return 0;
    if ((devDriverDesc.dpcTriCaps.dwTextureBlendCaps & 8) == 0) {
        if ((devDriverDesc.dpcTriCaps.dwTextureBlendCaps & 2) == 0) return 0;
        if ((devDriverDesc.dpcTriCaps.dwSrcBlendCaps & 1) != 0 && (devDriverDesc.dpcTriCaps.dwDestBlendCaps & 8) != 0)
            MyDirectDraw_instance.flags |= 0x40u;
    }
    MyDirectDraw_instance.texturesCount = 1;
    if ((MyDirectDraw_instance.flags & 0x20) != 0) {
        // #define D3DTEXOPCAPS_DISABLE                    0x00000001L
        if ((devDriverDesc.dwTextureOpCaps & 0x17) != 0) {
            MyDirectDraw_instance.flags |= 0x10u;
            MyDirectDraw_instance.texturesCount = 3;
            return 1;
        }
        MyDirectDraw_instance.flags &= ~0x30u;
        return 1;
    }
    if ((MyDirectDraw_instance.flags & 0x10) == 0) return 1;
    // #define D3DTEXOPCAPS_SELECTARG1                 0x00000002L
    // #define D3DTEXOPCAPS_SELECTARG2                 0x00000004L
    // #define D3DTEXOPCAPS_MODULATE2X                 0x00000010L
    if ((devDriverDesc.dwTextureOpCaps & 0x16) != 0) {
        MyDirectDraw_instance.texturesCount = 3;
        return 1;
    }
    MyDirectDraw_instance.flags &= ~0x30u;
    return 1;
}


bool __cdecl dk2::engine_drawScene(char a1) {
    g_unused765204 = 0;
    engine_setViewport(0, 0, g_sc_sceneWidth, g_sc_sceneHeight);
    if ((MyDirectDraw_instance.flags & 1) != 0) {
        if (a1) {
            render_clearBuffers(
                    g_sc_renderWidth, g_sc_renderHeight,
                    &MyDirectDraw_instance.buf[g_sc_sceneWidth * g_sc_renderTop + g_sc_renderLeft],
                    4 * g_sc_sceneWidth,
                    &MyDirectDraw_instance.maskBuf[g_sc_sceneWidth * g_sc_renderTop + g_sc_renderLeft],
                    2 * g_sc_sceneWidth);
            g_mgsr_drawMode = 0;
        } else {
            g_mgsr_drawMode ^= 1u;
        }
    } else {
        MyDirectDraw_instance.d3d3_halDevice->BeginScene();
    }
    draw3dScene();
    draw_tex_to_buf();
    static_CEngine2DPrimitive_clearList();
    if (g_unk_6BDEB8 < 0) {
        g_shadows_dword_780E70 = 0;
    } else {
        g_shadows_dword_780E70 = 1;
        static_SurfHashList2_sub_593640(
                g_unk_6BDEB8,
                g_camState.leftRight.x - -20.0,
                g_camState.leftRight.y - 20.0,
                g_camState.topBottom.x - -20.0,
                g_camState.topBottom.y - 20.0
        );
    }
    if ((MyDirectDraw_instance.flags & 1) != 0) {
        DDSURFACEDESC2 surfDesc;
        surfDesc.dwSize = sizeof(DDSURFACEDESC2);
        static_assert(sizeof(DDSURFACEDESC2) == 124);
        RECT rect {0, 0, g_sc_sceneWidth, g_sc_sceneHeight};
        if (!MyDirectDraw_instance.ddsurf4_offScreen->Lock(&rect, &surfDesc, 0x801, NULL)) {
            if (surfDesc.ddpfPixelFormat.dwRGBBitCount <= 16) {
                drawToSurface_mgsr(
                        &MyDirectDraw_instance.buf[g_sc_sceneWidth * g_sc_renderTop + g_sc_renderLeft],
                        (int) surfDesc.lpSurface + 2 * g_sc_renderLeft + g_sc_renderTop * surfDesc.lPitch,
                        g_sc_renderWidth, g_sc_renderHeight,
                        4 * g_sc_sceneWidth,
                        surfDesc.lPitch,
                        &MyDirectDraw_instance.maskBuf[g_sc_sceneWidth * g_sc_renderTop + g_sc_renderLeft],
                        2 * g_sc_sceneWidth,
                        0, 0);
            } else {
                drawToSurface32bit(
                        &MyDirectDraw_instance.buf[g_sc_sceneWidth * g_sc_renderTop + g_sc_renderLeft],
                        (int) surfDesc.lpSurface + 2 * g_sc_renderLeft + g_sc_renderTop * surfDesc.lPitch,
                        g_sc_renderWidth, g_sc_renderHeight,
                        4 * g_sc_sceneWidth,
                        surfDesc.lPitch,
                        &MyDirectDraw_instance.maskBuf[g_sc_sceneWidth * g_sc_renderTop + g_sc_renderLeft],
                        2 * g_sc_sceneWidth,
                        0, 0);
            }
            MyDirectDraw_instance.ddsurf4_offScreen->Unlock(NULL);
        }
    } else {
        MyDirectDraw_instance.d3d3_halDevice->EndScene();
    }
    g_unk_75CA88 = g_unk_765B10;
    NewObj571B3B_sub_576010();
//    void* v1;
//    ret_void_0args_0(v1);
    ++g_drawSceneCount_76520C;
    return g_sc_isCurDdSurfLost == 0;
}

void __cdecl dk2::engine_setViewport(uint32_t a1_x, uint32_t a2_y, uint32_t a3_width, uint32_t a4_height) {
    if ( (MyDirectDraw_instance_triangles.flags & 1) != 0 ) {
        grpoly_dword_frX = a1_x;
        grpoly_dword_toX = a1_x + a3_width;
        grpoly_dword_frY = a2_y;
        grpoly_dword_toY = a2_y + a4_height;
    } else {
        D3DVIEWPORT2 viewport;
        viewport.dwSize = sizeof(D3DVIEWPORT2);
        static_assert(sizeof(D3DVIEWPORT2) == 44);
        viewport.dwX = a1_x; viewport.dwY = a2_y;
        viewport.dwWidth = a3_width; viewport.dwHeight = a4_height;
        viewport.dvClipX = (float) a1_x; viewport.dvClipY = (float) a2_y;
        viewport.dvClipWidth = (float) a3_width; viewport.dvClipHeight = (float) a4_height;
        viewport.dvMinZ = 0.0; viewport.dvMaxZ = 1.0;
        MyDirectDraw_instance_triangles.d3d3_viewport->SetViewport2(&viewport);
    }
}

void __cdecl dk2::engine_setRenderArea(int posX, int posY, int width, int height) {
    g_sc_renderLeft = posX;
    g_sc_renderTop = posY;
    g_sc_renderWidth = width;
    g_sc_renderHeight = height;
    if(patch::big_resolution_fix::enabled) {  // don make screen area bigger than buffer size
        size_t bufWidth = client_rect.right - client_rect.left;
        size_t bufHeight = client_rect.bottom - client_rect.top;
        if(bufWidth != 0 && bufHeight != 0) {
            if(g_sc_renderWidth > bufWidth) g_sc_renderWidth = bufWidth;
            if(g_sc_renderHeight > bufHeight) g_sc_renderHeight = bufHeight;
        }
    }
}

void __cdecl dk2::setGammaRamp(const void *a1) {
    memcpy(&g_gammaRamp, a1, sizeof(g_gammaRamp));
    if (g_sc_is3dInitialized) {
        if ((MyDirectDraw_instance.flags & 2) != 0)
            g_sc_dd_gamma_control->SetGammaRamp(0, &g_gammaRamp);
    }
}

void dk2::updateGammaRamp() {
    if (g_sc_is3dInitialized) {
        if ((MyDirectDraw_instance.flags & 2) != 0)
            g_sc_dd_gamma_control->SetGammaRamp(0, &g_gammaRamp);
    }
}
