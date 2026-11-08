//
// Created by DiaLight on 1/24/2026.
//
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/CEngineDDSurface.h"
#include "dk2/MyDblNamedSurface.h"
#include "dk2/SurfHashList.h"
#include "dk2/SurfHashList2.h"
#include "dk2/CEngineSurface.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/RenderStageTex.h"
#include "dk2/SurfHashListItem.h"
#include "dk2/Triangle24.h"
#include "dk2/Triangle34.h"
#include "dk2/Vertex18.h"
#include "dk2/MyD3D3Vertex.h"
#include "dk2/utils/Uv2f_arr1024.h"
#include "patches/big_resolution_fix/big_resolution_fix.h"
#include "patches/logging.h"
#include "patches/opengl/opengl_patch.h"
#include "MyDirectDraw_flags.h"
#include "RenderState_flags.h"
#include <exception>
#include <string>


int __cdecl dk2::MyDirectDraw_init(
        LPDIRECTDRAW dd, LPDIRECTDRAWSURFACE ddOffScreen, LPDIRECTDRAWSURFACE ddPrimarySurf,
        GUID *deviceGuid, __int16 flags, int isLowResTexture
) {
    MyDblNamedSurface testCrossSurf;
    MyDblNamedSurface whiteTextureSurf;
    MyDblNamedSurface testLightSurf;

    MyDirectDraw_destroy();
    g_sc_is3dInitialized = 1;

    if(!patch::opengl_patch::enabled) {
        dd->QueryInterface(CLSID_IDirectDraw4, (LPVOID*) &MyDirectDraw_instance.dd4);
        ddOffScreen->QueryInterface(CLSID_IDirectDrawSurface4, (LPVOID*) &MyDirectDraw_instance.ddsurf4_offScreen);
        ddPrimarySurf->QueryInterface(
                CLSID_IDirectDrawSurface4,
                (LPVOID*) &MyDirectDraw_instance.ddsurf4_primarySurf);
    } else {
        MyDirectDraw_instance.ddsurf4_offScreen = (LPDIRECTDRAWSURFACE4) patch::opengl_patch::addRef(ddOffScreen, true);
        MyDirectDraw_instance.ddsurf4_primarySurf = (LPDIRECTDRAWSURFACE4) patch::opengl_patch::addRef(ddPrimarySurf, true);
    }
    MyDirectDraw_instance.reductionLevel = isLowResTexture;
    MyDirectDraw_instance.flags = flags;

    DDSURFACEDESC surfDesc;
    memset(&surfDesc, 0, sizeof(surfDesc));
    surfDesc.dwSize = sizeof(DDSURFACEDESC);
    static_assert(sizeof(DDSURFACEDESC) == 108);

    if(patch::opengl_patch::enabled) {
        patch::opengl_patch::getViewportDesc(ddOffScreen, surfDesc);
    } else {
        ddOffScreen->GetSurfaceDesc(&surfDesc);
    }
    g_sc_sceneWidth = surfDesc.dwWidth;
    g_sc_sceneHeight = surfDesc.dwHeight;
    g_sc_renderLeft = 0;
    g_sc_renderTop = 0;
    g_sc_renderWidth = surfDesc.dwWidth;
    g_sc_renderHeight = surfDesc.dwHeight;
    if(patch::big_resolution_fix::enabled) {  // extend buffer size
        surfDesc.dwWidth = MyWindow_instance.dwWidth;
        surfDesc.dwHeight = MyWindow_instance.dwHeight;
    }
    if ((MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
        if(patch::opengl_patch::enabled) {
            patch::log::err("should not happen");
            throw std::exception("should not happen");
        }
        // Martin Griffiths MMX Software Renderer
        MyDirectDraw_instance.buf = init_mgsr(ddOffScreen, &MyDirectDraw_instance.maskBuf, surfDesc.dwWidth, surfDesc.dwHeight);
        g_sc_grpoly_mydd_maskBuf = MyDirectDraw_instance.maskBuf;
        g_sc_grpoly_mydd_buf = MyDirectDraw_instance.buf;
        g_sc_mgsr_maskBuf_pitch = 2 * g_sc_sceneWidth;
        g_sc_mgsr_buf_pitch = 4 * g_sc_sceneWidth;
        g_sc_mgsr_initialized = 1;
    } else {
        if(patch::opengl_patch::enabled) {
            patch::opengl_patch::createViewport();
        } else {
            MyDirectDraw_instance.dd4->QueryInterface(CLSID_IDirect3D3, (LPVOID*) &MyDirectDraw_instance.d3d3);
            if (
                    MyDirectDraw_instance.d3d3->CreateViewport(&MyDirectDraw_instance.d3d3_viewport, NULL) ||
                    MyDirectDraw_instance.d3d3->CreateDevice(CLSID_IDirect3DHALDevice, MyDirectDraw_instance.ddsurf4_offScreen, &MyDirectDraw_instance.d3d3_halDevice, NULL
                    )) {
                MyDirectDraw_destroy();
                return 0;
            }
            MyDirectDraw_instance.d3d3_halDevice->AddViewport(MyDirectDraw_instance.d3d3_viewport);
            MyDirectDraw_instance.d3d3_halDevice->SetCurrentViewport(MyDirectDraw_instance.d3d3_viewport);
        }
    }
    if (!configureFlagsAndTexturesCount() || !static_MyDirectDraw_devTexture_init(&MyDirectDraw_instance)) {
        MyDirectDraw_destroy();
        return 0;
    }
    if ((MyDirectDraw_instance.flags & MyDirectDraw_useGammaRamps) != 0) {
        if(patch::opengl_patch::enabled) {
            patch::opengl_patch::setGammaRamp(g_gammaRamp);
        } else {
            MyDirectDraw_instance.ddsurf4_primarySurf->QueryInterface(
                    CLSID_IDirectDrawGammaControl,
                    (LPVOID*) &g_sc_dd_gamma_control);
            if (g_sc_is3dInitialized) {
                if ((MyDirectDraw_instance.flags & MyDirectDraw_useGammaRamps) != 0)
                    g_sc_dd_gamma_control->SetGammaRamp(0, &g_gammaRamp);
            }
        }
    }
    static_MyDirectDraw_triangles_init(&MyDirectDraw_instance);
    static_MyDirectDraw_uvs_init(&MyDirectDraw_instance);
    shadows_init();
    testLightSurf.constructor("EngineTestLight", "EngineTestLight", 16, 0, 1);
    EngineTestLight_a31x400_idx = MyEntryBuf_MyScaledSurface_create(&testLightSurf, 1);
    testCrossSurf.constructor("EngineTestCross", "EngineTestCross", 16, 0, 1);
    EngineTestCross_a31x400_idx = MyEntryBuf_MyScaledSurface_create(&testCrossSurf, 1);
    whiteTextureSurf.constructor("EngineTextureWhite", "EngineTextureWhite", 0, 0, 1);
    EngineTextureWhite_a31x400_idx = MyEntryBuf_MyScaledSurface_create(&whiteTextureSurf, 1);
    g_sc_isCurDdSurfLost = 0;
    return 1;
}

void dk2::MyDirectDraw_destroy() {
    if (!g_sc_is3dInitialized) return;
//    void *v0;
//    ret_void_0args_0(v0);
    MyDirectDraw_uvs_destroy();
    MyDirectDraw_triangles_destroy();
    MyDirectDraw_devTexture_destroy();
    if ((MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
        if (g_sc_mgsr_initialized)
            sc_release_mgsr();
        g_sc_mgsr_initialized = 0;
    } else {
        if (MyDirectDraw_instance.d3d3_halDevice) MyDirectDraw_instance.d3d3_halDevice->Release();
        if (MyDirectDraw_instance.d3d3) MyDirectDraw_instance.d3d3->Release();
        MyDirectDraw_instance.d3d3_halDevice = NULL;
        MyDirectDraw_instance.d3d3 = NULL;
    }
    if (g_sc_dd_gamma_control)
        g_sc_dd_gamma_control->Release();
    if(!patch::opengl_patch::enabled) {
        if (MyDirectDraw_instance.ddsurf4_primarySurf)
            MyDirectDraw_instance.ddsurf4_primarySurf->Release();
        if (MyDirectDraw_instance.ddsurf4_offScreen)
            MyDirectDraw_instance.ddsurf4_offScreen->Release();
    } else {
        patch::opengl_patch::releaseOglTexture(MyDirectDraw_instance.ddsurf4_primarySurf);
        patch::opengl_patch::releaseOglTexture(MyDirectDraw_instance.ddsurf4_offScreen);
    }
    if (MyDirectDraw_instance.dd4)
        MyDirectDraw_instance.dd4->Release();
    g_sc_dd_gamma_control = NULL;
    MyDirectDraw_instance.dd4 = NULL;
    MyDirectDraw_instance.ddsurf4_primarySurf = NULL;
    MyDirectDraw_instance.ddsurf4_offScreen = NULL;
    g_sc_is3dInitialized = 0;
}

void dk2::MyDirectDraw_triangles_destroy() {
    if ((MyDirectDraw_instance_triangles.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
        if (g_MyEntryBuf_Vertex18_instance.maxCount) {
            MyHeap_free(g_MyEntryBuf_Vertex18_instance.buf);
            g_MyEntryBuf_Vertex18_instance.maxCount = 0;
        }
        for (int i = 0; i < 2; ++i) {
            MyHeap_free(g_vertices[i].vertices18x2);
            g_vertices[i].vertices18x2 = NULL;
        }
    } else {
        if (g_GlobalToLocal_indicesMap.maxCount) {
            MyHeap_free(g_GlobalToLocal_indicesMap.buf);
            g_GlobalToLocal_indicesMap.maxCount = 0;
        }
        MyHeap_free(g_MyD3D3Vertex_buf);
        g_MyD3D3Vertex_buf = NULL;
        for (int i = 0; i < 2; ++i) {
            MyHeap_free(g_vertices[i].MyD3D3Vertices);
            g_vertices[i].MyD3D3Vertices = NULL;
        }
    }
    if (g_MyEntryBuf_Triangle24_instance.maxCount) {
        MyHeap_free(g_MyEntryBuf_Triangle24_instance.buf);
        g_MyEntryBuf_Triangle24_instance.maxCount = 0;
    }
    if (g_MyEntryBuf_Triangle34_instance.maxCount) {
        MyHeap_free(g_MyEntryBuf_Triangle34_instance.buf);
        g_MyEntryBuf_Triangle34_instance.maxCount = 0;
    }
}

namespace {
    void dump(LPDDPIXELFORMAT lpDDPixFmt, std::string &out) {
        char buf[1024];
        sprintf(buf, "DDPIXELFORMAT ddfmt {\n");out += buf;
        sprintf(buf, "    .dwSize=0x%X,\n", lpDDPixFmt->dwSize);out += buf;
        sprintf(buf, "    .dwFlags=0x%X,\n", lpDDPixFmt->dwFlags);out += buf;
        sprintf(buf, "    .dwRGBBitCount=0x%X,\n", lpDDPixFmt->dwRGBBitCount);out += buf;
        sprintf(buf, "    .dwRBitMask=0x%X,\n", lpDDPixFmt->dwRBitMask);out += buf;
        sprintf(buf, "    .dwGBitMask=0x%X,\n", lpDDPixFmt->dwGBitMask);out += buf;
        sprintf(buf, "    .dwBBitMask=0x%X,\n", lpDDPixFmt->dwBBitMask);out += buf;
        sprintf(buf, "    .dwRGBAlphaBitMask=0x%X,\n", lpDDPixFmt->dwRGBAlphaBitMask);out += buf;
        sprintf(buf, "};\n");out += buf;
    }
}
namespace {
    int calcBitcount(unsigned int mask) {
        int bitcount = 0;
        for (unsigned int i = 0; i <= 31; ++i) {
            if ((1 << i) > mask)
                break;
            if ((mask & (1 << i)) != 0)
                ++bitcount;
        }
        return bitcount;
    }
}

int __cdecl dk2::static_MyDirectDraw_devTexture_init(MyDirectDraw *mydd) {
    MyDirectDraw_devTexture_destroy();
    // destruct if flag changed
    if (((MyDirectDraw_instance_devTexture.flags ^ mydd->flags) & MyDirectDraw_isSoftware3D_MMX) != 0) {
        for (MyCESurfHandle *i = g_surfh_first; i; i = i->gnext) {
            if ((i->reductionLevel_andFlags & 0x200) == 0) {
                if (i->cesurf) i->cesurf->v_scalar_destructor(1u);
                i->cesurf = NULL;
            }
        }
    }
    MyDirectDraw_instance_devTexture = *mydd;
    g_isSupports_4r4g4b4a = 0;
    g_isSupports_8r8g8b8a = 0;
    g_isSupports_16bit = 0;
    g_surfDesc_bgra32_0.constructor(0xFF000000, 0xFF0000u, 0xFF00u, 0xFFu, 32);
    if ((MyDirectDraw_instance_devTexture.flags & MyDirectDraw_isSoftware3D_MMX) != 0) {
        MyCEngineSurfDesc_bgra32_instance.constructor(0xFF000000, 0xFF0000u, 0xFF00u, 0xFFu, 32);
        SurfHashList *obj = (SurfHashList *) MyHeap_alloc(sizeof(SurfHashList));
        SurfHashList *v7;
        if (obj) {
            for (int x = 0; x < 5; ++x) {
                for (int y = 0; y < 5; ++y) {
                    obj->arr5x5[x][y] = NULL;
                }
            }
            obj->f6C = 0;
            obj->stageTexs_first = NULL;
            obj->stageTexs_count = 0;
            obj->surfh_first = NULL;
            v7 = obj;
        } else {
            v7 = NULL;
        }
        g_pSurfHashList = v7;
        int numHolders = 24;
        if (patch::big_resolution_fix::enabled) {
            numHolders *= 4;
        }
        v7->constructor(&MyCEngineSurfDesc_bgra32_instance, numHolders);
    } else {
        if(!patch::opengl_patch::enabled) {
            MyDirectDraw_instance_devTexture.d3d3_halDevice->EnumTextureFormats(
                    [](LPDDPIXELFORMAT lpDDPixFmt, LPVOID lpContext) -> HRESULT {
                        std::string out;
                        if ((lpDDPixFmt->dwFlags & 0x40) != 0) {  // DDPF_RGB  The RGB data in the pixel format structure is valid.
                            int rBits = calcBitcount(lpDDPixFmt->dwRBitMask);
                            int gBits = calcBitcount(lpDDPixFmt->dwGBitMask);
                            int bBits = calcBitcount(lpDDPixFmt->dwBBitMask);
                            int aBits = calcBitcount(lpDDPixFmt->dwRGBAlphaBitMask);
                            if ((MyDirectDraw_instance_devTexture.flags & MyDirectDraw_32BITTEXTURES) != 0) {
                                if (g_isSupports_8r8g8b8a)
                                    return 1;
                                if (rBits == 8 && gBits == 8 && bBits == 8 && aBits == 8) {
                                    MyCEngineSurfDesc_bgra32_instance.initFromPixelFormat(lpDDPixFmt);
                                    dump(lpDDPixFmt, out);
                                    int result = 1;
                                    g_isSupports_8r8g8b8a = 1;
                                    return result;
                                }
                            }
                            if (!g_isSupports_4r4g4b4a) {
                                if (rBits == 4 && gBits == 4 && bBits == 4 && aBits == 4) {
                                    MyCEngineSurfDesc_bgra32_instance.initFromPixelFormat(lpDDPixFmt);
                                    dump(lpDDPixFmt, out);
                                    int result = 1;
                                    g_isSupports_4r4g4b4a = 1;
                                    return result;
                                }
                                if (!g_isSupports_8r8g8b8a && rBits == 8 && gBits == 8 && bBits == 8 && aBits == 8) {
                                    MyCEngineSurfDesc_bgra32_instance.initFromPixelFormat(lpDDPixFmt);
                                    dump(lpDDPixFmt, out);
                                    int result = 1;
                                    g_isSupports_8r8g8b8a = 1;
                                    return result;
                                }
                            }
                        } else if (lpDDPixFmt->dwRGBBitCount == 16) {
                            if ((MyDirectDraw_instance_devTexture.flags & 0x20) != 0) {
                                if ((lpDDPixFmt->dwFlags & 0x40000) == 0)  // DDPF_BUMPLUMINANCE
                                    return 1;
                            } else if ((lpDDPixFmt->dwFlags & 0x80000) == 0) {  // DDPF_BUMPDUDV
                                return 1;
                            }
                            MyCEngineSurfDesc_unk16_instance.initFromPixelFormat(lpDDPixFmt);
                            dump(lpDDPixFmt, out);
                            g_isSupports_16bit = 1;
                        }
                        return 1;
                    }, NULL);
        } else {
            {
                DDPIXELFORMAT ddfmt {
                        .dwSize=0x20, .dwFlags=0x41, .dwRGBBitCount=0x20,
                        .dwRBitMask=0xFF0000, .dwGBitMask=0xFF00, .dwBBitMask=0xFF, .dwRGBAlphaBitMask=0xFF000000,
                };
                MyCEngineSurfDesc_bgra32_instance.initFromPixelFormat(&ddfmt);
                g_isSupports_8r8g8b8a = 1;
            }
            {
                DDPIXELFORMAT ddfmt {
                        .dwSize=0x20, .dwFlags=0x80000, .dwRGBBitCount=0x10,
                        .dwRBitMask=0xFF, .dwGBitMask=0xFF00, .dwBBitMask=0x0, .dwRGBAlphaBitMask=0x0,
                };
                MyCEngineSurfDesc_unk16_instance.initFromPixelFormat(&ddfmt);
                g_isSupports_16bit = 1;
            }
        }
        if (!g_isSupports_4r4g4b4a && !g_isSupports_8r8g8b8a) return 0;
        char v14 = 1;
        if (!g_isSupports_16bit) {
            MyDirectDraw_instance_devTexture.flags &= ~(MyDirectDraw_isBumpmappingSimpleEnabled | MyDirectDraw_isBumpmappingLuminanceEnabled);
        } else {
            if ((MyDirectDraw_instance_devTexture.flags & (MyDirectDraw_isBumpmappingSimpleEnabled | MyDirectDraw_isBumpmappingLuminanceEnabled)) != 0) {
                SurfHashList2 *v15 = (SurfHashList2 *) MyHeap_alloc(sizeof(SurfHashList2));
                SurfHashList2 *v20;
                if (v15) {
                    for (int y = 0; y < 5; ++y) {
                        for (int x = 0; x < 5; ++x) {
                            v15->arr5x5_surfh[x][y] = NULL;
                            v15->arr5x5[x][y] = NULL;
                        }
                    }
                    v15->f8count = 0;
                    v15->stageTex_first = NULL;
                    v15->stageTex_count = 0;
                    v15->surfh_first = NULL;
                    v15->ddsurf = NULL;
                    v20 = v15;
                } else {
                    v20 = NULL;
                }
                g_pSurfHashList2 = v20;
                v14 = v20->constructor(&MyCEngineSurfDesc_unk16_instance, 2, 2) & 1;
            }
            if (!g_isSupports_16bit) {
                MyDirectDraw_instance_devTexture.flags &= ~0x30u;
            }
        }
        SurfHashList2 *v21 = (SurfHashList2 *) MyHeap_alloc(sizeof(SurfHashList2));
        SurfHashList2 *v26;
        if (v21) {
            for (int y = 0; y < 5; ++y) {
                for (int x = 0; x < 5; ++x) {
                    v21->arr5x5_surfh[x][y] = NULL;
                    v21->arr5x5[x][y] = NULL;
                }
            }
            v21->f8count = 0;
            v21->stageTex_first = NULL;
            v21->stageTex_count = 0;
            v21->surfh_first = NULL;
            v21->ddsurf = NULL;
            v26 = v21;
        } else {
            v26 = NULL;
        }
        pSurfHashList2_2 = v26;
        if (((unsigned __int8) v26->constructor(&MyCEngineSurfDesc_bgra32_instance, 32, 512) & (unsigned __int8) v14) ==
            0) {
            SurfHashList2_initialized = 1;
            MyDirectDraw_devTexture_destroy();
            return 0;
        }
    }
    if (MyTextures_instance.f430) {
        MyTextures_instance.texNameToFileOffsetMap.cleanup();
        MyTextures_instance.f430 = 0;
        if (MyTextures_instance.fileHandle)
            dk2::__fclose(MyTextures_instance.fileHandle);
        MyTextures_instance.fileHandle = NULL;
    }
    MyTextures_instance.f430 = 1;
    int v29 = 0;
    if (MyTextures_instance.rwfile.open(MyTextures_instance.textureCacheFile_dir, "TCHC", &v29) && v29 == 4) {
        int count = 0;
        MyTextures_instance.rwfile.readInt(&count, 4u);
        for (int k = 0; k < count; ++k) {
            void *value = NULL;
            char name[256];
            MyTextures_instance.rwfile.readString(name);
            MyTextures_instance.rwfile.readInt(&value, 4u);
            MyTextures_instance.texNameToFileOffsetMap.put(name, value);
        }
        MyTextures_instance.rwfile.sub_57A6F0();
    } else {
        patch::log::err("failed to open texture file TCHC");
    }
    MyTextures_instance.fileHandle = dk2::__fopen(MyTextures_instance.textureCacheFile_dat, "rb");
    if (!MyTextures_instance.fileHandle) {
        patch::log::err("failed to open texture cache file");
    }
    SurfHashList2_initialized = 1;
    CEngineSurface *v9 = (CEngineSurface *) MyHeap_alloc(0x18);
    CEngineSurface *v30 = v9;
    int try_level = 0;
    CEngineSurface *v10;
    if (v9) {
        v10 = v9->constructor(128, 128, &g_surfDesc_bgra32_0);
    } else {
        v10 = NULL;
    }
    try_level = -1;
    CEngineSurfaceScaler_instance.orig_128x128_8a8r8g8b = v10;
    CEngineSurface *v11 = (CEngineSurface *) MyHeap_alloc(sizeof(CEngineSurface));
    v30 = v11;
    try_level = 1;
    CEngineSurface *v12;
    if (v11) {
        v12 = v11->constructor(128, 128, &g_surfDesc_bgra32_0);
    } else {
        v12 = NULL;
    }
    CEngineSurfaceScaler_instance.scaled_128x128_8a8r8g8b = v12;
    return 1;
}


void dk2::MyDirectDraw_devTexture_destroy() {
    if (!SurfHashList2_initialized) return;
    if (CEngineSurfaceScaler_instance.orig_128x128_8a8r8g8b)
        CEngineSurfaceScaler_instance.orig_128x128_8a8r8g8b->v_scalar_destructor(1u);
    if (CEngineSurfaceScaler_instance.scaled_128x128_8a8r8g8b)
        CEngineSurfaceScaler_instance.scaled_128x128_8a8r8g8b->v_scalar_destructor(1u);
    CEngineSurfaceScaler_instance.orig_128x128_8a8r8g8b = NULL;
    CEngineSurfaceScaler_instance.scaled_128x128_8a8r8g8b = NULL;
    if ((MyDirectDraw_instance.flags & MyDirectDraw_isSoftware3D_MMX) == 0) {
        if(!patch::opengl_patch::enabled) {
            for (int i = 0; i < MyDirectDraw_instance_devTexture.texturesCount; ++i) {
                MyDirectDraw_instance_devTexture.d3d3_halDevice->SetTexture(i, 0);
            }
        }
    }
    if (SurfHashList2 *v1 = pSurfHashList2_2) {
        for (RenderStageTex *j = pSurfHashList2_2->stageTex_first; j; j = j->prev_)
            v1->deleteHolders(j);
    }
    if (SurfHashList2 *v3 = g_pSurfHashList2) {
        for (RenderStageTex *k = g_pSurfHashList2->stageTex_first; k; k = k->prev_)
            v3->deleteHolders(k);
    }
    if (g_pSurfHashList)
        g_pSurfHashList->markAndDeleteP1of4_recursive();
    if (SurfHashList2 *v5 = pSurfHashList2_2) {
        RenderStageTex *v6 = NULL;
        if (pSurfHashList2_2->stageTex_first) {
            RenderStageTex *f14_next;
            do {
                RenderStageTex *fD8_holder_first = v5->stageTex_first;
                f14_next = fD8_holder_first->prev_;
                fD8_holder_first->prev_ = v6;
                v6 = v5->stageTex_first;
                v5->stageTex_first = f14_next;
            } while (f14_next);
        }
        if (v6) {
            RenderStageTex *v9;
            do {
                v9 = v6->prev_;
                if (v6) {
                    v6->fun_591F30();
                    MyHeap_free(v6);
                }
                v6 = v9;
            } while (v9);
        }
        if (CEngineDDSurface *fD0_ddsurf = v5->ddsurf)
            fD0_ddsurf->v_scalar_destructor(1u);
        v5->ddsurf = NULL;
        MyHeap_free(pSurfHashList2_2);
        pSurfHashList2_2 = NULL;
    }
    if (SurfHashList2 *v11 = g_pSurfHashList2) {
        RenderStageTex *v12 = 0;
        if (g_pSurfHashList2->stageTex_first) {
            RenderStageTex *v13;
            do {
                v13 = v11->stageTex_first->prev_;
                v11->stageTex_first->prev_ = v12;
                v12 = v11->stageTex_first;
                v11->stageTex_first = v13;
            } while (v13);
        }
        if (v12) {
            RenderStageTex *v14;
            do {
                v14 = v12->prev_;
                if (v12) {
                    v12->fun_591F30();
                    MyHeap_free(v12);
                }
                v12 = v14;
            } while (v14);
        }
        if (CEngineDDSurface *v15 = v11->ddsurf)
            v15->v_scalar_destructor(1u);
        v11->ddsurf = NULL;
        MyHeap_free(g_pSurfHashList2);
        g_pSurfHashList2 = NULL;
    }
    if (g_pSurfHashList) {
        g_pSurfHashList->clear();
        MyHeap_free(g_pSurfHashList);
        g_pSurfHashList = NULL;
    }
    if (MyTextures_instance.f430) {
        MyTextures_instance.texNameToFileOffsetMap.cleanup();
        MyTextures_instance.f430 = 0;
        if (MyTextures_instance.fileHandle)
            dk2::__fclose(MyTextures_instance.fileHandle);
        MyTextures_instance.fileHandle = NULL;
    }
    SurfHashList2_initialized = 0;
}

void __cdecl dk2::static_MyDirectDraw_triangles_init(MyDirectDraw *a1) {
    memcpy(&MyDirectDraw_instance_triangles, a1, sizeof(MyDirectDraw_instance_triangles));
    g_mgsr_currentDrawFlags = 0;
    g_texStage = 1;
    if ( (MyDirectDraw_instance_triangles.flags & MyDirectDraw_isSoftware3D_MMX) != 0 ) {
        mgsr_pDrawFun = mgsr_drawFuns[48];
        mgsr_setDrawFun(0);
        static_assert((sizeof(Vertex18) * 512) == 0x3000);
        g_MyEntryBuf_Vertex18_instance.buf = (Vertex18 *)MyHeap_alloc(sizeof(Vertex18) * 512);
        g_MyEntryBuf_Vertex18_instance.expandCount = 512;
        g_MyEntryBuf_Vertex18_instance.maxCount = 512;
        for (int k = 0; k < 2; ++k) {
            g_vertices[k].vertices18x2 = (Vertex18 *)MyHeap_alloc(0x6000);
        }
        g_MyEntryBuf_Triangle34_instance.buf = (Triangle34 *)MyHeap_alloc(sizeof(Triangle34) * 512);
        g_MyEntryBuf_Triangle34_instance.expandCount = 512;
        g_MyEntryBuf_Triangle34_instance.maxCount = 512;
    } else {
        int texCount = MyDirectDraw_instance_triangles.texturesCount;
        g_MyD3D3Vertex_size = 8 * texCount + 0x14;

        if(patch::opengl_patch::enabled) {
            patch::opengl_patch::configureRenderState();
        } else {
            g_MyD3D3Vertex_dwTypeDesc =
                    (texCount << D3DFVF_TEXCOUNT_SHIFT) | (D3DFVF_DIFFUSE | D3DFVF_XYZRHW);
            static_assert((D3DFVF_DIFFUSE | D3DFVF_XYZRHW) == 0x44);
            MyDirectDraw_instance_triangles.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_SHADEMODE, 2);
            MyDirectDraw_instance_triangles.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_TEXTUREPERSPECTIVE, 1);
            MyDirectDraw_instance_triangles.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_DITHERENABLE, 1);
            MyDirectDraw_instance_triangles.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_CULLMODE, 1);
            MyDirectDraw_instance_triangles.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_SPECULARENABLE, 0);
            MyDirectDraw_instance_triangles.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_SUBPIXEL, 1);
            MyDirectDraw_instance_triangles.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_ZFUNC, 4);
            MyDirectDraw_instance_triangles.d3d3_halDevice->SetTextureStageState(0, D3DTSS_COLORARG1, 2);
            MyDirectDraw_instance_triangles.d3d3_halDevice->SetTextureStageState(0, D3DTSS_COLORARG2, 0);
            MyDirectDraw_instance_triangles.d3d3_halDevice->SetTextureStageState(0, D3DTSS_COLOROP, 4);
            MyDirectDraw_instance_triangles.d3d3_halDevice->SetTextureStageState(0, D3DTSS_ALPHAARG1, 2);
            MyDirectDraw_instance_triangles.d3d3_halDevice->SetTextureStageState(0, D3DTSS_ALPHAARG2, 0);
            MyDirectDraw_instance_triangles.d3d3_halDevice->SetTextureStageState(0, D3DTSS_ALPHAOP, 4);
            for (int i = 0; i < MyDirectDraw_instance_triangles.texturesCount; ++i ) {
                MyDirectDraw_instance_triangles.d3d3_halDevice->SetTextureStageState(i, D3DTSS_TEXCOORDINDEX, i);
                MyDirectDraw_instance_triangles.d3d3_halDevice->SetTextureStageState(i, D3DTSS_ADDRESS, 1);
            }
            MyDirectDraw_prepareTexture(0);
        }
        g_MyD3D3Vertex_maxCount = 512;
        g_MyD3D3Vertex_buf = MyHeap_alloc(g_MyD3D3Vertex_size * 512);
        g_GlobalToLocal_indicesMap.buf = (uint16_t *) MyHeap_alloc(sizeof(uint16_t) * 512);
        for (unsigned int j = 0; j < 512; ++j ) g_GlobalToLocal_indicesMap.buf[j] = -1;
        g_GlobalToLocal_indicesMap.expandCount = 512;
        g_GlobalToLocal_indicesMap.maxCount = 512;
        for (int k = 0; k < 2; ++k) {
            g_vertices[k].MyD3D3Vertices = (MyD3D3Vertex *)MyHeap_alloc(g_MyD3D3Vertex_size * 1024);
        }
    }
    g_MyEntryBuf_Triangle24_instance.expandCount = 512;
    g_MyEntryBuf_Triangle24_instance.maxCount = 512;
    static_assert((sizeof(Triangle24) * 512) == 0x4800);
    g_MyEntryBuf_Triangle24_instance.buf = (Triangle24 *)MyHeap_alloc(sizeof(Triangle24) * 512);
}

void __cdecl dk2::static_MyDirectDraw_uvs_init(MyDirectDraw *a1) {
    memcpy(&MyDirectDraw_instance_uvs, a1, sizeof(MyDirectDraw_instance_uvs));
    static_assert((sizeof(Uv2f_arr1024) * 4) == 0x8000);
    g_Uv2f_arr4x1024 = (Uv2f_arr1024 *)MyHeap_alloc(sizeof(Uv2f_arr1024) * 4);
}

inline DWORD F2DW( FLOAT f ) { return *((DWORD*)&f); }
void __cdecl dk2::MyDirectDraw_prepareTexture(int flags) {
    if (flags == g_mgsr_currentDrawFlags) return;
    unsigned int useStages = g_texStage;
    // --- Handle features that were disabled ---
    int disabledFlags = g_mgsr_currentDrawFlags & ~flags;
    IDirect3DDevice3 *dev = MyDirectDraw_instance_triangles.d3d3_halDevice;
    if (disabledFlags) {
        if ((disabledFlags & (RenderState_bumpMapLuminance | RenderState_bumpMapSimple)) != 0) {
            dev->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
            dev->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
            dev->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);

            dev->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
            dev->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
            dev->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
            useStages = 1;
        }
        constexpr uint32_t blendFlags = RenderState_alphaBlendInvSrc | RenderState_alphaBlendSrc | RenderState_fl2 | RenderState_alphaBlendOne;
        static_assert(blendFlags == 0x1023);
        if ((disabledFlags & blendFlags) != 0 && (flags & blendFlags) == 0) {
            dev->SetRenderState(D3DRENDERSTATE_DESTBLEND, D3DBLEND_ZERO);
            dev->SetRenderState(D3DRENDERSTATE_SRCBLEND, D3DBLEND_ONE);
            dev->SetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, FALSE);
        }
        if ((disabledFlags & RenderState_diffuseAlpha) != 0) {
            dev->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
            dev->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_CURRENT);
            dev->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
        }
        if ((disabledFlags & RenderState_zWriteEnable) != 0) {
            dev->SetRenderState(D3DRENDERSTATE_ZWRITEENABLE, FALSE);
        }
        if ((disabledFlags & RenderState_zEnable) != 0) {
            dev->SetRenderState(D3DRENDERSTATE_ZENABLE, FALSE);
        }
        if ((disabledFlags & RenderState_linearFiltering) != 0) {
            for (int i = 0; i < MyDirectDraw_instance_triangles.texturesCount; ++i) {
                dev->SetTextureStageState(i, D3DTSS_MAGFILTER, D3DTFG_POINT);
                dev->SetTextureStageState(i, D3DTSS_MINFILTER, D3DTFG_POINT);
            }
        }
    }
    // --- Handle features that were enabled ---
    int enabledFlags = ~g_mgsr_currentDrawFlags & flags;
    if (enabledFlags) {
        if ((enabledFlags & RenderState_alphaBlendOne) != 0) {
            dev->SetRenderState(D3DRENDERSTATE_SRCBLEND, D3DBLEND_ONE);
            dev->SetRenderState(D3DRENDERSTATE_DESTBLEND, D3DBLEND_ONE);
            dev->SetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, TRUE);
        }
        if ((enabledFlags & RenderState_alphaBlendSrc) != 0) {
            dev->SetRenderState(D3DRENDERSTATE_SRCBLEND, D3DBLEND_SRCALPHA);
            dev->SetRenderState(D3DRENDERSTATE_DESTBLEND, D3DBLEND_INVSRCALPHA);
            dev->SetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, TRUE);
        }
        if ((enabledFlags & RenderState_diffuseAlpha) != 0) {
            dev->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_SELECTARG1);
            dev->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_DIFFUSE);
            dev->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_CURRENT);
        }
        if ((enabledFlags & RenderState_alphaBlendInvSrc) != 0) {
            dev->SetRenderState(D3DRENDERSTATE_SRCBLEND, D3DBLEND_ZERO);
            dev->SetRenderState(D3DRENDERSTATE_DESTBLEND, D3DBLEND_INVSRCCOLOR);
            dev->SetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, TRUE);
        }
        if ((enabledFlags & RenderState_zWriteEnable) != 0) {
            dev->SetRenderState(D3DRENDERSTATE_ZWRITEENABLE, TRUE);
        }
        if ((enabledFlags & RenderState_zEnable) != 0) {
            dev->SetRenderState(D3DRENDERSTATE_ZENABLE, TRUE);
        }
        static_assert((RenderState_bumpMapLuminance | RenderState_linearFiltering | RenderState_zEnable | RenderState_useLightSplat | RenderState_zWriteEnable) == 0x105C0);
        if ((enabledFlags & RenderState_linearFiltering) != 0) {
            for (int j = 0; j < MyDirectDraw_instance_triangles.texturesCount; ++j) {
//                dev->SetTextureStageState(j, D3DTSS_MAGFILTER, D3DTFG_LINEAR);
//                dev->SetTextureStageState(j, D3DTSS_MINFILTER, D3DTFG_LINEAR);

                dev->SetTextureStageState(j, D3DTSS_MAGFILTER, D3DTFG_ANISOTROPIC);
                dev->SetTextureStageState(j, D3DTSS_MINFILTER, D3DTFG_FLATCUBIC);
            }
        }
        if (((enabledFlags & (RenderState_bumpMapSimple | RenderState_bumpMapLuminance)) != 0)) {
            dev->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
            dev->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
            dev->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);

            dev->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
            dev->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
            dev->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);


            if ((enabledFlags & RenderState_bumpMapSimple) != 0) {
                dev->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_BUMPENVMAP);
                dev->SetTextureStageState(1, D3DTSS_COLORARG1, D3DTA_TEXTURE);
                dev->SetTextureStageState(1, D3DTSS_COLORARG2, D3DTA_CURRENT);
            }
            if ((enabledFlags & RenderState_bumpMapLuminance) != 0) {
                dev->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_BUMPENVMAPLUMINANCE);
                dev->SetTextureStageState(1, D3DTSS_COLORARG1, D3DTA_TEXTURE);
                dev->SetTextureStageState(1, D3DTSS_COLORARG2, D3DTA_CURRENT);
            }

            dev->SetTextureStageState(1, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
            dev->SetTextureStageState(1, D3DTSS_BUMPENVMAT00, F2DW(1.0f));
            dev->SetTextureStageState(1, D3DTSS_BUMPENVMAT01, F2DW(0.0f));
            dev->SetTextureStageState(1, D3DTSS_BUMPENVMAT10, F2DW(0.0f));
            dev->SetTextureStageState(1, D3DTSS_BUMPENVMAT11, F2DW(1.0f));

            dev->SetTextureStageState(1, D3DTSS_BUMPENVLSCALE, F2DW(1.0f));
            dev->SetTextureStageState(1, D3DTSS_BUMPENVLOFFSET, F2DW(0.0f));


            dev->SetTextureStageState(2, D3DTSS_COLORARG1, D3DTA_TEXTURE);
            dev->SetTextureStageState(2, D3DTSS_COLORARG2, D3DTA_CURRENT);
            dev->SetTextureStageState(2, D3DTSS_COLOROP, D3DTOP_ADD);

            dev->SetTextureStageState(2, D3DTSS_ALPHAOP, D3DTOP_DISABLE);

            useStages = 3;
        }
    }
    for (int i = useStages; i < g_texStage; ++i) {
        dev->SetTextureStageState(i, D3DTSS_COLOROP, D3DTOP_DISABLE);
        dev->SetTextureStageState(i, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
    }
    g_texStage = useStages;
    g_mgsr_currentDrawFlags = flags;
}


void __cdecl dk2::MyDirectDraw_DrawTriangleList(uint32_t bufIdx, uint32_t surfCount, uint32_t verticesCount) {
    // [x:f,y:f,z:f,rhw:f][diff:dd][x:f,y:f]*texCount  // D3DFVF_DIFFUSE | D3DFVF_XYZRHW
    MyDirectDraw_instance_triangles.d3d3_halDevice->DrawIndexedPrimitive(
            D3DPT_TRIANGLELIST, g_MyD3D3Vertex_dwTypeDesc,
            g_vertices[bufIdx].MyD3D3Vertices, verticesCount,
            (LPWORD) g_DrawTriangleList_lpwIndices, 3 * surfCount,
            D3DDP_DONOTCLIP | D3DDP_DONOTUPDATEEXTENTS | D3DDP_DONOTLIGHT
    );
    static_assert((D3DDP_DONOTCLIP | D3DDP_DONOTUPDATEEXTENTS | D3DDP_DONOTLIGHT) == 0x1C);

    bool isSoftware3D_MMX = (MyDirectDraw_instance_triangles.flags & MyDirectDraw_isSoftware3D_MMX) != 0;
    if (!g_dword_76D2FC || isSoftware3D_MMX) return;

    for (int i = 0; i < g_DrawTriangleList_verticesCount; i++) {
        auto *ver = (MyD3D3Vertex *) ((char *) g_vertices[0].MyD3D3Vertices + g_MyD3D3Vertex_size * i);
        ver->diffuse = -1;
    }

    DWORD textureHandle;
    MyDirectDraw_instance_triangles.d3d3_halDevice->GetRenderState(D3DRENDERSTATE_TEXTUREHANDLE, &textureHandle);
    DWORD fillMode;
    MyDirectDraw_instance_triangles.d3d3_halDevice->GetRenderState(D3DRENDERSTATE_FILLMODE, &fillMode);
    DWORD zFunc;
    MyDirectDraw_instance_triangles.d3d3_halDevice->GetRenderState(D3DRENDERSTATE_ZFUNC, &zFunc);

    MyDirectDraw_instance_triangles.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_FILLMODE, D3DFILL_WIREFRAME);
    MyDirectDraw_instance_triangles.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_TEXTUREHANDLE, 0);
    MyDirectDraw_instance_triangles.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_ZFUNC, D3DCMP_ALWAYS);

    MyDirectDraw_instance_triangles.d3d3_halDevice->DrawIndexedPrimitive(
            D3DPT_TRIANGLELIST, g_MyD3D3Vertex_dwTypeDesc,
            g_vertices[0].MyD3D3Vertices, verticesCount,
            (LPWORD) g_DrawTriangleList_lpwIndices, 3 * surfCount,
            0
    );

    MyDirectDraw_instance_triangles.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_ZFUNC, zFunc);
    MyDirectDraw_instance_triangles.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_FILLMODE, fillMode);
    MyDirectDraw_instance_triangles.d3d3_halDevice->SetRenderState(D3DRENDERSTATE_TEXTUREHANDLE, textureHandle);
}

