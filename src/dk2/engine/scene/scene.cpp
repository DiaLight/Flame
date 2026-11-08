//
// Created by DiaLight on 1/22/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/Triangle24.h"
#include "dk2/RenderStageTex.h"
#include "dk2/engine/primitive/CEnginePrimitiveBase.h"
#include "patches/big_resolution_fix/big_resolution_fix.h"
#include "patches/logging.h"
#include "patches/opengl/opengl_patch.h"
#include "MyDirectDraw_flags.h"
#include "dk2/engine/game_engine.h"
#include "tools/visual_debug.h"
#include <exception>

int dk2::configureFlagsAndTexturesCount() {
    if(!patch::opengl_patch::enabled) {
        DDCAPS caps;
        memset(&caps, 0, sizeof(caps));
        static_assert(sizeof(DDCAPS) == 380);
        caps.dwSize = sizeof(DDCAPS);
        MyDirectDraw_instance.dd4->GetCaps(&caps, NULL);
        static_assert(DDCAPS2_PRIMARYGAMMA == 0x20000);
        if ((caps.dwCaps2 & DDCAPS2_PRIMARYGAMMA) == 0)
            MyDirectDraw_instance.flags &= ~MyDirectDraw_useGammaRamps;  // disable has gamma ramps
    }
    if ((MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
        MyDirectDraw_instance.flags &= ~MyDirectDraw_isBumpmappingSimpleEnabled;
        MyDirectDraw_instance.texturesCount = 1;
        return 1;
    }

    if(!patch::opengl_patch::enabled) {
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
                MyDirectDraw_instance.flags |= MyDirectDraw_unc40;
        }
        MyDirectDraw_instance.texturesCount = 1;
        if ((MyDirectDraw_instance.flags & MyDirectDraw_isBumpmappingLuminanceEnabled) != 0) {
            // #define D3DTEXOPCAPS_DISABLE                    0x00000001L
            if ((devDriverDesc.dwTextureOpCaps & 0x17) != 0) {
                MyDirectDraw_instance.flags |= MyDirectDraw_isBumpmappingSimpleEnabled;
                MyDirectDraw_instance.texturesCount = 3;
                return 1;
            }
            MyDirectDraw_instance.flags &= ~0x30u;
            return 1;
        }
        if ((MyDirectDraw_instance.flags & MyDirectDraw_isBumpmappingSimpleEnabled) != 0) {
            // #define D3DTEXOPCAPS_SELECTARG1                 0x00000002L
            // #define D3DTEXOPCAPS_SELECTARG2                 0x00000004L
            // #define D3DTEXOPCAPS_MODULATE2X                 0x00000010L
            if ((devDriverDesc.dwTextureOpCaps & 0x16) != 0) {
                MyDirectDraw_instance.texturesCount = 3;
                return 1;
            }

            MyDirectDraw_instance.flags &= ~0x30u;
        }
    } else {
        MyDirectDraw_instance.flags |= MyDirectDraw_isBumpmappingLuminanceEnabled;
        MyResources_instance.video_settings.bumpMappingConfig = 2;

        MyDirectDraw_instance.texturesCount = 1;
        if ((MyDirectDraw_instance.flags & MyDirectDraw_isBumpmappingLuminanceEnabled) != 0) {  // video_settings.isBumpmappingEnabled == 2
            MyDirectDraw_instance.flags |= MyDirectDraw_isBumpmappingSimpleEnabled;
            MyDirectDraw_instance.texturesCount = 3;  // CEngineDynamicHeightField with MyDirectDraw_isBumpmappingSimpleEnabled(video_settings.isBumpmappingEnabled == 1) require 3 textures
        }
    }
    return 1;
}


bool __cdecl dk2::engine_drawScene(char a1) {
    g_unused765204 = 0;
    engine_setViewport(0, 0, g_sc_sceneWidth, g_sc_sceneHeight);
    if(patch::opengl_patch::enabled) {
        patch::opengl_patch::beginScene();
    } else if ((MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
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

    group_SceneObject2E_by_AtlasMeshGroup_andDraw();
    draw3d_second();

    Meshes2D_byConstructor_clear();
    if (g_visualDebugAtlasEnabled < 0) {
        g_shadows_dword_780E70 = 0;
    } else {
        g_shadows_dword_780E70 = 1;
        static_SurfHashList2_visualDebugAtlas(
                g_visualDebugAtlasEnabled,
                g_activeCameraState.leftRight.x - -20.0,
                g_activeCameraState.leftRight.y - 20.0,
                g_activeCameraState.topBottom.x - -20.0,
                g_activeCameraState.topBottom.y - 20.0
        );
    }
    if(patch::opengl_patch::enabled) {
        patch::opengl_patch::endScene();
    } else if ((MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
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
    if(patch::opengl_patch::enabled && patch::opengl_patch::clearSurf2) {
//        patch::opengl_patch::fillWithColor(dk2::g_primarySurf, NULL, dk2::Bgraf {0, 0, 0, 0, 0});
//        patch::opengl_patch::fillWithColor(dk2::g_offScreen, NULL, dk2::Bgraf {0, 0, 0, 0, 0});
        patch::opengl_patch::fillWithColor(*MyWindow_instance.getCurOffScreenSurf(), NULL, dk2::Bgraf {0, 0, 0, 0, 0});
    }
    g_unk_75CA88 = g_unk_765B10;
    NewObj571B3B_sub_576010();
//    void* v1;
//    ret_void_0args_0(v1);
    ++g_drawSceneCount_76520C;
    return g_sc_isCurDdSurfLost == 0;
}

void __cdecl dk2::engine_setViewport(uint32_t a1_x, uint32_t a2_y, uint32_t a3_width, uint32_t a4_height) {
    if(patch::opengl_patch::enabled) {
        patch::opengl_patch::setViewport(a1_x, a2_y, a3_width, a4_height);
        return;
    }
    if ( (MyDirectDraw_instance_triangles.flags & MyDirectDraw_isSoftware3D_MMX) != 0 ) {
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
        size_t bufWidth = g_clientRect.right - g_clientRect.left;
        size_t bufHeight = g_clientRect.bottom - g_clientRect.top;
        if(bufWidth != 0 && bufHeight != 0) {
            if(g_sc_renderWidth > bufWidth) g_sc_renderWidth = bufWidth;
            if(g_sc_renderHeight > bufHeight) g_sc_renderHeight = bufHeight;
        }
    }
}

void __cdecl dk2::setGammaRamp(const void *a1) {
    memcpy(&g_gammaRamp, a1, sizeof(g_gammaRamp));
    if (g_sc_is3dInitialized) {
        if(patch::opengl_patch::enabled) {
            patch::opengl_patch::setGammaRamp(g_gammaRamp);
        } else {
            if ((MyDirectDraw_instance.flags & MyDirectDraw_useGammaRamps) != 0)
                g_sc_dd_gamma_control->SetGammaRamp(0, &g_gammaRamp);
        }
    }
}

void dk2::updateGammaRamp() {
    if (g_sc_is3dInitialized) {
        if ((MyDirectDraw_instance.flags & MyDirectDraw_useGammaRamps) != 0)
            g_sc_dd_gamma_control->SetGammaRamp(0, &g_gammaRamp);
    }
}

void dk2::draw3d_second() {
    if ((MyDirectDraw_instance_triangles.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
        drawSoftware3D_MMX();
    } else {
        drawHardware3D();
    }
}

void dk2::drawHardware3D() {
    int ren_surfCount = 0;
    DWORD ren_dst_vertexIdx = 0;
    Idx3us *ren_pIndices = NULL;

    // state
    RenderStageTex *tri_pHolders_x4[4];
    memset(tri_pHolders_x4, 0, sizeof(tri_pHolders_x4));
    int tri_renderFlags = 0;
    DWORD tri_surfhCount = 0;
    int tri_idx = 1024;
    Triangle24 *pTriangle = NULL;
    while (true) {

        while (pTriangle == NULL) {
            if (tri_idx < 1024) {
                g_sceneObj2E_f21_to_triangleIndices[tri_idx] = -1;
            }
            --tri_idx;
            if (tri_idx < 0) break;
            int idx_ = g_sceneObj2E_f21_to_triangleIndices[tri_idx];
            if (idx_ < 0) continue;
            pTriangle = &g_MyEntryBuf_Triangle24_instance.buf[idx_];
        }

        bool doDrawTriangles = false;
        // build vertices and indices while same props and same amount of stages and surfCount < 256
        // if any texture of any stage was changed, also perform render call
        if (!pTriangle
            || pTriangle->renderFlags != tri_renderFlags
            || pTriangle->surfhCount != tri_surfhCount
            || ren_surfCount >= 256) {
            doDrawTriangles = true;
        } else {
            for (int i = 0; i < tri_surfhCount; ++i) {
                if (pTriangle->holders[i] == tri_pHolders_x4[i]) continue;
                doDrawTriangles = true;
                break;
            }
        }

        if (doDrawTriangles) {
            if (ren_surfCount) {
                // clear indices refs
                for (int j = 0; j < ren_surfCount; ++j) {
                    Triangle24 *pTriangle24 = g_drawnTrianglesArr[j];
                    for (int i = 0; i < 3; ++i) {
                        g_GlobalToLocal_indicesMap.buf[pTriangle24->vertIdxs[i]] = -1;
                    }
                }
                // stage: holder->surf-(as CEngineDDSurface)->devTex

                if(patch::opengl_patch::enabled) {
                    patch::opengl_patch::drawCall(
                            tri_renderFlags,  // render state
                            tri_pHolders_x4, tri_surfhCount,  // textures
                            g_vertices[0].MyD3D3Vertices, dk2::g_MyD3D3Vertex_size, ren_dst_vertexIdx,  // vertices
                            g_DrawTriangleList_lpwIndices, ren_surfCount  // indices
                    );
                } else {
                    // apply render flags
                    MyDirectDraw_prepareTexture(tri_renderFlags);

                    // bind stage textures to stages
                    for (int stage = 0; stage < tri_surfhCount; ++stage) {
                        renderer_bindStageTexture(tri_pHolders_x4[stage], stage);
                    }
                    // draw
                    MyDirectDraw_DrawTriangleList(0, ren_surfCount, ren_dst_vertexIdx);
                }
                ren_surfCount = 0;
                ren_dst_vertexIdx = 0;
            }

            if (!pTriangle) {
                break;
            }
            ren_pIndices = g_DrawTriangleList_lpwIndices;
            tri_surfhCount = pTriangle->surfhCount;
            for (int i = 0; i < tri_surfhCount; ++i) {
                tri_pHolders_x4[i] = pTriangle->holders[i];
            }
            tri_renderFlags = pTriangle->renderFlags;
        }

        {
            // add vertices and indices to render
            for (int i = 0; i < 3; ++i) {
                int src_vertexIdx = pTriangle->vertIdxs[i];
                int idx = (int16_t) g_GlobalToLocal_indicesMap.buf[src_vertexIdx];
                if (idx < 0) {
                    // add triangle vertice
                    g_GlobalToLocal_indicesMap.buf[src_vertexIdx] = ren_dst_vertexIdx;
                    idx = ren_dst_vertexIdx;
                    memcpy(
                            (BYTE *) g_vertices[0].MyD3D3Vertices + g_MyD3D3Vertex_size * ren_dst_vertexIdx,
                            (BYTE *) g_MyD3D3Vertex_buf + g_MyD3D3Vertex_size * src_vertexIdx,
                            g_MyD3D3Vertex_size
                    );
                    ren_dst_vertexIdx++;
                }
                ((uint16_t *) ren_pIndices)[i] = idx;
            }
            ren_pIndices++;
        }
        g_drawnTrianglesArr[ren_surfCount++] = pTriangle;
        pTriangle = pTriangle->prevTriangleIdx >= 0 ? &g_MyEntryBuf_Triangle24_instance.buf[pTriangle->prevTriangleIdx] : NULL;
    }
    g_totalTrianglesCount = 0;
    g_totalVerticesCount = 0;
    g_Triangle34_count = 0;
}

void dk2::Meshes2D_byConstructor_clear() {
    g_pCEngine2DPrimitive_initialized = 0;
    for (CEnginePrimitiveBase *toRemove = g_Meshes2D_byConstructor_last; toRemove; ) {
        CEnginePrimitiveBase *prev = toRemove->f0_byConstructor_prev;

        toRemove->f0_byConstructor_prev = NULL;
        if (toRemove) toRemove->v_deleting_destructor(1);

        toRemove = prev;
    }
    g_Meshes2D_byConstructor_last = NULL;
}
