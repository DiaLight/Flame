//
// Created by DiaLight on 12.09.2024.
//
#include <Windows.h>
#include "WinEventHandlers.h"
#include "dk2/DxD3dInfo.h"
#include "dk2/DxDeviceInfo.h"
#include "dk2/DxModeInfo.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "game_engine.h"
#include "gog_exports.h"
#include "gog_patch.h"
#include "patches/logging.h"
#include "patches/opengl/opengl_patch.h"
#include "dk2/resources/file/MyFile.h"
#include "dk2/engine/scene/MyDdSurface_flags.h"


namespace dk2 {

    int ge_resolveDevices() {
        if (g_ge_ddraw_device_count != 0) return g_ge_ddraw_device_count;
        LPDDENUMCALLBACKA lpCallback = [](LPGUID lpGUID, LPSTR lpDeviceDesc, LPSTR lpDeviceName, LPVOID p) -> BOOL {
            int device_idx = g_ge_ddraw_device_count;
            DxDeviceInfo *devs;
            if ( g_ge_ddraw_device_count ) {
                static_assert(sizeof(DxDeviceInfo) == 0x21A);
                devs = (DxDeviceInfo *) dk2::_realloc(g_ge_ddraw_devices, sizeof(DxDeviceInfo) * (g_ge_ddraw_device_count + 1));
            } else {
                devs = (DxDeviceInfo *) dk2::_malloc_1(538u);
            }
            g_ge_ddraw_devices = devs;
            int device_offs = device_idx;
            if (lpGUID) {
                devs[device_idx].pGuid = &devs[device_idx].guid;
                g_ge_ddraw_devices[device_idx].guid = *lpGUID;
            } else {
                devs[device_idx].pGuid = NULL;
            }
            lstrcpyA(g_ge_ddraw_devices[device_offs].desc, lpDeviceDesc);
            lstrcpyA(g_ge_ddraw_devices[device_offs].name, lpDeviceName);
            g_ge_ddraw_devices[device_offs].modeListCount = 0;
            g_ge_ddraw_devices[device_offs].modeList = NULL;
            g_ge_ddraw_devices[device_offs].infoListCount = 0;
            g_ge_ddraw_devices[device_offs].infoList = NULL;

            LPDIRECTDRAW lpDD;
            if(*o_gog_enabled) {
                fake_DirectDrawCreate(lpGUID, &lpDD, NULL);
            } else {
                DirectDrawCreate(lpGUID, &lpDD, NULL);
            }

            static_assert(sizeof(DDCAPS_DX7) == 380);
            g_ge_ddraw_devices->ddcaps.dwSize = sizeof(DDCAPS_DX7);
            lpDD->GetCaps(&g_ge_ddraw_devices->ddcaps, NULL);

            DxDeviceInfo *ddraw_device = &g_ge_ddraw_devices[device_offs];
            ddraw_device->dwVendorId = 0;
            ddraw_device->dwDeviceId = 0;

            IDirectDraw4 *dd4;
            DDDEVICEIDENTIFIER ddDevId;
            if (SUCCEEDED(lpDD->QueryInterface(CLSID_IDirectDraw4, (LPVOID *)&dd4))
                && SUCCEEDED(dd4->GetDeviceIdentifier(&ddDevId, 1)) ) {
                ddraw_device->dwVendorId = ddDevId.dwVendorId;
                ddraw_device->dwDeviceId = ddDevId.dwDeviceId;
                dd4->Release();
            }
            g_ge_ddraw_devices[device_offs].isVendor121A = 0;
            if ( g_ge_ddraw_devices[device_offs].dwVendorId == 0x121A ) {
                int f212_dwDeviceId = g_ge_ddraw_devices[device_offs].dwDeviceId;
                if ( f212_dwDeviceId == 1 || f212_dwDeviceId == 2 ) {
                    g_ge_ddraw_devices[device_offs].isVendor121A = 1;
                }
            }
            IDirect3D *d3d;
            lpDD->QueryInterface(CLSID_IDirect3D, (LPVOID *)&d3d);
            d3d->EnumDevices([](GUID FAR *lpGuid, LPSTR lpDeviceDescription, LPSTR lpDeviceName,
                                LPD3DDEVICEDESC lpDesc1, LPD3DDEVICEDESC lpDesc2, LPVOID p) -> HRESULT {
                int devIdx = (int) p;
                DxDeviceInfo& deviceInfo = g_ge_ddraw_devices[devIdx];

                if ( strstr(lpDeviceName, "Ramp") || strstr(lpDeviceName, "RGB Emulation") )
                    return 1;

                int infoIdx = deviceInfo.infoListCount;
                if ( infoIdx )
                    deviceInfo.infoList = (DxD3dInfo *) dk2::_realloc(deviceInfo.infoList, sizeof(DxD3dInfo) * (infoIdx + 1));
                else
                    deviceInfo.infoList = (DxD3dInfo *) dk2::_malloc_1(sizeof(DxD3dInfo));
                DxD3dInfo& dxD3DInfo = deviceInfo.infoList[infoIdx];
                {
                    if ( lpGuid ) {
                        dxD3DInfo.pGuid = &dxD3DInfo.guid;
                        dxD3DInfo.guid = *lpGuid;
                    } else {
                        dxD3DInfo.pGuid = NULL;
                    }
                    lstrcpyA(dxD3DInfo.desc, lpDeviceDescription);
                    lstrcpyA(dxD3DInfo.name, lpDeviceName);
                    LPD3DDEVICEDESC desc_ = lpDesc1;
                    if ( lpDesc1->dwFlags ) {
                        dxD3DInfo.hasDesc = 1;
                    } else {
                        desc_ = lpDesc2;
                        dxD3DInfo.hasDesc = 0;
                    }
                    dxD3DInfo.devDesc = *desc_;
                    dxD3DInfo.f192 = 0;
                    dxD3DInfo.texCapsAnd1 = dxD3DInfo.devDesc.dpcTriCaps.dwTextureCaps & 1;
                    dxD3DInfo.hasZbuffer = dxD3DInfo.devDesc.dwDeviceZBufferBitDepth != 0;
                }
                ++deviceInfo.infoListCount;
                return DDENUMRET_OK;
            }, (LPVOID) device_idx);
            d3d->Release();
            lpDD->Release();
            ++g_ge_ddraw_device_count;
            return TRUE;
        };
        if(*o_gog_enabled) {
            fake_DirectDrawEnumerateA(lpCallback, NULL);
        } else {
            DirectDrawEnumerateA(lpCallback, NULL);
        }
        return g_ge_ddraw_device_count;
    }

}

BOOL __cdecl dk2::ge_isDeviceSuitableForGame(int devIdx) {
    DxD3dInfo *info = g_ge_ddraw_devices[devIdx].infoList;
    if (!info) return FALSE;
    if (!info->hasDesc) return FALSE;
    if (!info->texCapsAnd1) return FALSE;
    if (!info->hasZbuffer) return FALSE;
    D3DDEVICEDESC desc = info->devDesc;
    if (!(desc.dpcTriCaps.dwTextureCaps & D3DPTFILTERCAPS_NEAREST)) return FALSE;
    if (!(desc.dpcTriCaps.dwTextureFilterCaps & D3DPTFILTERCAPS_LINEAR)) return FALSE;
    return TRUE;
}


int dk2::ge_getDeviceIdxSuitableForGame() {
    int devCount = ge_resolveDevices();
    for (int i = 0; i < devCount; ++i) {
        if(!ge_isDeviceSuitableForGame(i)) continue;
        return i;
    }
    return -1;
}


namespace dk2 {

    void ge_fillDDrawList(dk2::MyWindow *window) {
        window->dds_count = 0;
        LPDDENUMCALLBACKA lpCallback = [](LPGUID lpGuid, LPSTR lpDeviceDesc, LPSTR lpDeviceName, LPVOID lpContext) -> BOOL {
            MyWindow *window = (MyWindow *) lpContext;
            if (lpGuid) {
                window->guid_arr16[window->dds_count] = *lpGuid;
                window->is_empty_dd[window->dds_count] = 0;
            } else {
                window->is_empty_dd[window->dds_count] = 1;
            }
            strncpy(window->dds__names_arr16[window->dds_count], lpDeviceName, 64);
            window->dds__names_arr16[window->dds_count][63] = '\0';
            strncpy(window->dds__descs_arr16[window->dds_count], lpDeviceDesc, 64);
            window->dds__descs_arr16[window->dds_count][63] = '\0';
            window->dds_count++;
            return TRUE;
        };
        if(*o_gog_enabled) {
            fake_DirectDrawEnumerateA(lpCallback, window);
        } else {
            DirectDrawEnumerateA(lpCallback, window);
        }
    }

    void ge_collectDisplayModes() {
        if (g_ge_dd_index != 0) return;
        LPDDENUMCALLBACKA lpCallback = [](LPGUID lpGuid, LPSTR lpDeviceDesc, LPSTR lpDeviceName, LPVOID lpContext) -> BOOL {
            HWND hWindow = (HWND) lpContext;
            LPDIRECTDRAW lpDD;
            if(*o_gog_enabled) {
                fake_DirectDrawCreate(lpGuid, &lpDD, NULL);
            } else {
                DirectDrawCreate(lpGuid, &lpDD, NULL);
            }
            lpDD->SetCooperativeLevel(hWindow, DDSCL_EXCLUSIVE | DDSCL_NOWINDOWCHANGES | DDSCL_FULLSCREEN);
            DxDeviceInfo& dev = g_ge_ddraw_devices[g_ge_dd_index];
            dev.modeListCount = 0;
            lpDD->EnumDisplayModes(0, NULL, (LPVOID) g_ge_dd_index, [](LPDDSURFACEDESC lpDesc, LPVOID lpContext) -> HRESULT {
                int idx = (int) lpContext;
                DxDeviceInfo& dev = g_ge_ddraw_devices[idx];
                int count = dev.modeListCount;
                DxModeInfo* ddraw_mode;
                if (count) {
                    ddraw_mode = (DxModeInfo*) dk2::_realloc(
                        dev.modeList,
                        sizeof(DxModeInfo) * (count + 1)
                    );
                } else {
                    ddraw_mode = (DxModeInfo*) dk2::_malloc_1(sizeof(DxModeInfo));
                }
                dev.modeList = ddraw_mode;
                int mode_idx = count;
                DxModeInfo& scrMode = dev.modeList[mode_idx];
                scrMode.dwWidth = lpDesc->dwWidth;
                scrMode.dwHeight = lpDesc->dwHeight;
                scrMode.dwRGBBitCount = lpDesc->ddpfPixelFormat.dwRGBBitCount;
                scrMode.hasFlag_shr5and1 = (lpDesc->ddpfPixelFormat.dwFlags >> 5) & 1;
                ++dev.modeListCount;
                return DDENUMRET_OK;
            });
            lpDD->SetCooperativeLevel(hWindow, DDSCL_NORMAL);
            lpDD->Release();
            ++g_ge_dd_index;
            return TRUE;
        };
        if(*o_gog_enabled) {
            fake_DirectDrawEnumerateA(lpCallback, getHWindow());
        } else {
            DirectDrawEnumerateA(lpCallback, getHWindow());
        }
    }

    void inline_selectDrawEngine(dk2::MyWindow *window) {
        ge_fillDDrawList(window);
        ge_resolveDevices();
        ge_collectDisplayModes();
        int selectedDdIdx = -1;
        if (!MyResources_instance.video_settings.cmd_flag_SOFTWARE) {
            if (cmd_flag_DDD) {
                window->selected_dd_idx = cmd_flag_DDD_value;
                return;
            }
            if (MyResources_instance.video_settings.guid_index < g_ge_ddraw_device_count
                && MyResources_instance.video_settings.guid_index_verifier_working) {
                window->selected_dd_idx = MyResources_instance.video_settings.guid_index;
                return;
            }
            selectedDdIdx = ge_getDeviceIdxSuitableForGame();
        }
        if (selectedDdIdx < 0) {
            // software render engine
            MyResources_instance.video_settings.setSelected3dEngine(4);
            MyResources_instance.video_settings.writeGuidIndex(0);
            window->selected_dd_idx = 0;
        } else {
            MyResources_instance.video_settings.setSelected3dEngine(2);
            MyResources_instance.video_settings.writeGuidIndex(selectedDdIdx);
            window->selected_dd_idx = selectedDdIdx;
        }
    }

    HRESULT initDisplayMode(int initFlags, DWORD coopLvl, DWORD width, DWORD height, DWORD displayBitness) {
        int hres_2 = g_dk2dd->SetCooperativeLevel(g_hWnd, coopLvl);
        if (hres_2 < 0) return hres_2;
        if ((initFlags & MyDdSurface_isWindowed) != 0) {
            hres_2 = g_dk2dd->CreateClipper(0, &g_lpDDClipper, NULL);
            if (hres_2 < 0) return hres_2;
            hres_2 = g_lpDDClipper->SetHWnd(0, g_hWnd);
            if (hres_2 < 0) return hres_2;
            return hres_2;
        }
        hres_2 = g_dk2dd->SetDisplayMode(width, height, displayBitness);
        return hres_2;
    }

    void showTodoMessageBox(const char *Format, ...) {
        char Buffer[2048];
        va_list ArgList;

        va_start(ArgList, Format);
        vsprintf(Buffer, Format, ArgList);
        ge_showMessageBox(g_hWnd, Buffer, "TO DO", 0x2000u);
    }

    int *ge_dk2dd_init(
        int *pstatus, uint32_t width, uint32_t height,
        uint32_t displayBitness, int initFlags, LPPALETTEENTRY entries_
    ) {
        if (FPUControlWordWithState_instance.initialized)
            FPUControlWordWithState_instance.ctl.apply();
        if ((initFlags & 4) != 0) {
            initFlags = initFlags | 2;
        }
        if ((initFlags & MyDdSurface_isWindowed) != 0) {
            if ((initFlags & 2) != 0) {
                return *pstatus = -1, pstatus;
            }
            initFlags |= MyDdSurface_screenSwap;
        }
        callWinEvent_ev0_ty6(0);
        ge_ddReleaseSurfaces();
        IDirectDraw* pdd = g_dk2dd;
        if (!g_dk2dd) {
            int status;
            int status1_ = *ge_createDirectDrawObject(&status, g_selectedDDGuid, &g_dk2dd);
            if (status1_ < 0) {
                ge_dk2dd_destroy();
                showTodoMessageBox("Failed to create Direct Draw object");
                return *pstatus = status1_, pstatus;
            }
            pdd = g_dk2dd;
        }
        int isWindowed = initFlags & MyDdSurface_isWindowed;
        if ((initFlags & MyDdSurface_isWindowed) != 0) {
            DDSURFACEDESC dispMode;
            memset(&dispMode, 0, sizeof(dispMode));
            dispMode.dwSize = 0x6C;
            int hres_1 = pdd->GetDisplayMode(&dispMode);
            if (hres_1 < 0) {
                return *pstatus = hres_1, pstatus;
            }
            if (dispMode.ddpfPixelFormat.dwRGBBitCount != displayBitness) {
                return *pstatus = -1, pstatus;
            }
            pdd = g_dk2dd;
        }
        setSurfaceDD(pdd);
        HWND HWindow = g_hBullfrogWindow;
        if (!g_hBullfrogWindow)
            HWindow = getHWindow();
        g_hWnd = HWindow;
        ShowWindow(HWindow, 5);
        if (g_hWnd) {
            MSG msg;
            while (PeekMessageA(&msg, NULL, 0, 0, 1u)) {
                DefWindowProcA(msg.hwnd, msg.message, msg.wParam, msg.lParam);
            }
        }
        Sleep(0);
        g_isNeedBlt = 1;
        g_ignore_79D3E0 = 1;
        DWORD coopLvl;
        if ((initFlags & MyDdSurface_isWindowed) != 0) {
            coopLvl = DDSCL_NORMAL;
        } else {
            coopLvl = DDSCL_ALLOWMODEX | DDSCL_EXCLUSIVE | DDSCL_FULLSCREEN;
        }
        if ((initFlags & MyDdSurface_FPUControlWord) != 0) {
            coopLvl |= DDSCL_FPUSETUP;
            FPUControlWordWithState_instance.initialized = 1;
            FPUControlWordWithState_instance.ctl.change(0x3F, 1); // extended precision and all mask
        }
        int hres_2 = initDisplayMode(initFlags, coopLvl, width, height, displayBitness);
        if (hres_2 < 0) {
            ge_dk2dd_destroy();
            return *pstatus = hres_2, pstatus;
        }
        PALETTEENTRY* entries = entries_;
        if (entries_) {
            memcpy(g_paletteEntries, entries_, sizeof(g_paletteEntries));
        } else {
            for (int i = 0; i < 256; ++i) {
                PALETTEENTRY& palette = g_paletteEntries[i];
                palette.peRed = i;
                palette.peGreen = 0;
                palette.peBlue = i;
            }
        }
        if (displayBitness == 8) {
            if (!entries_)
                entries = g_paletteEntries;
            hres_2 = g_dk2dd->CreatePalette(68, entries, &g_lpDDPalette, 0);
            if (hres_2 < 0) {
                ge_dk2dd_destroy();
                return *pstatus = hres_2, pstatus;
            }
        } else {
            if (g_lpDDPalette)
                g_lpDDPalette->Release();
            g_lpDDPalette = NULL;
        }
        DDSURFACEDESC surfaceDesc;
        memset(&surfaceDesc, 0, sizeof(surfaceDesc));
        surfaceDesc.dwSize = 0x6C;
        surfaceDesc.dwFlags = 1;
        surfaceDesc.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE;
        static_assert(DDSCAPS_PRIMARYSURFACE == 0x200);
        if ((initFlags & 2) != 0) {
            surfaceDesc.dwFlags = DDSD_BACKBUFFERCOUNT | DDSD_CAPS;
            static_assert((DDSD_BACKBUFFERCOUNT | DDSD_CAPS) == 0x21);
            surfaceDesc.ddsCaps.dwCaps = DDSCAPS_PRIMARYSURFACE | DDSCAPS_FLIP | DDSCAPS_COMPLEX;
            static_assert((DDSCAPS_PRIMARYSURFACE | DDSCAPS_FLIP | DDSCAPS_COMPLEX) == 0x218);
            surfaceDesc.dwBackBufferCount = ((initFlags & MyDdSurface_extraBackBuffer) != 0) + 1;
        }
        if ((initFlags & MyDdSurface_3DDEVICE) != 0) {  // can query d3device from surface
            surfaceDesc.ddsCaps.dwCaps |= DDSCAPS_3DDEVICE;
        }
        int hres = g_dk2dd->CreateSurface(&surfaceDesc, &g_primarySurf.dd_surf.dd_surface, 0);
        if (hres < 0) {
            g_primarySurf.dd_surf.dd_surface = NULL;
            if (hres == 0x88760234) {
                g_primarySurf.dd_surf.dd_surface = NULL;
                g_dk2dd->SetCooperativeLevel(g_hWnd, DDSCL_NORMAL);
                ge_dk2dd_destroy();
                return *pstatus = hres, pstatus;
            }
            g_dk2dd->SetCooperativeLevel(g_hWnd, DDSCL_NORMAL);

            g_primarySurf.dd_surf.dd_surface = NULL;
            ge_dk2dd_destroy();
            return *pstatus = hres, pstatus;
        }
        hres = g_primarySurf.dd_surf.dd_surface->GetSurfaceDesc(&surfaceDesc);
        if (hres < 0) {
            g_primarySurf.dd_surf.dd_surface->Release();
            g_primarySurf.dd_surf.dd_surface = NULL;
            ge_dk2dd_destroy();
            return *pstatus = hres, pstatus;
        }
        g_isSurfModeX = surfaceDesc.ddsCaps.dwCaps & DDSCAPS_MODEX;
        static_assert(DDSCAPS_MODEX == 0x200000);
        if ((surfaceDesc.ddsCaps.dwCaps & DDSCAPS_MODEX) != 0 && (initFlags & MyDdSurface_screenSwap) != 0) {
            g_primarySurf.dd_surf.dd_surface->Release();
            g_primarySurf.dd_surf.dd_surface = NULL;
            surfaceDesc.dwFlags = 0x21;
            surfaceDesc.ddsCaps.dwCaps = 0x218;
            surfaceDesc.dwBackBufferCount = 1;
            hres = g_dk2dd->CreateSurface(&surfaceDesc, &g_primarySurf.dd_surf.dd_surface, 0);
            if (hres < 0) {
                g_primarySurf.dd_surf.dd_surface = NULL;
                ge_dk2dd_destroy();
                return *pstatus = hres, pstatus;
            }
            DDSCAPS hdc;
            hdc.dwCaps = 4;
            int hresult = g_primarySurf.dd_surf.dd_surface->GetAttachedSurface( &hdc, &Obj79D1C0_instance.pPrimaryAttachedSurf);
            if (hresult < 0) return *pstatus = hresult, pstatus;
        }
        int hres_3;
        if ((initFlags & 2) != 0) {
            DDSCAPS hdc;
            hdc.dwCaps = 4;
            hres_3 = g_primarySurf.dd_surf.dd_surface->GetAttachedSurface(
                &hdc,
                &g_offScreen.dd_surf.dd_surface);
            if (hres_3 < 0) {
                return *pstatus = hres_3, pstatus;
            }
        } else {
            surfaceDesc.dwFlags = 7;
            surfaceDesc.dwHeight = height;
            DWORD v22 = (initFlags & MyDdSurface_videoMemory) != 0
                    ? (DDSCAPS_VIDEOMEMORY | DDSCAPS_OFFSCREENPLAIN)
                    : (DDSCAPS_SYSTEMMEMORY | DDSCAPS_OFFSCREENPLAIN);
            static_assert((DDSCAPS_VIDEOMEMORY | DDSCAPS_OFFSCREENPLAIN) == 0x4040);
            static_assert((DDSCAPS_SYSTEMMEMORY | DDSCAPS_OFFSCREENPLAIN) == 0x840);
            surfaceDesc.dwWidth = width;
            surfaceDesc.ddsCaps.dwCaps = v22;
            if ((initFlags & MyDdSurface_3DDEVICE) != 0) {
                v22 |= DDSCAPS_3DDEVICE;
                static_assert(DDSCAPS_3DDEVICE == 0x2000u);
                surfaceDesc.ddsCaps.dwCaps = v22;
            }
            hres_3 = g_dk2dd->CreateSurface(&surfaceDesc, &g_offScreen.dd_surf.dd_surface, NULL);
        }
        if (g_offScreen.dd_surf.dd_surface) {
            if (isWindowed) {
                g_primarySurf.dd_surf.dd_surface->SetClipper(g_lpDDClipper);
                if (displayBitness != 8) {
                    MyDdSurface_constructor(&g_primarySurf.dd_surf, width, height, displayBitness, initFlags);
                    MyDdSurface_constructor(&g_offScreen.dd_surf, width, height, displayBitness, initFlags);
                    g_pCurOffScreen = &g_offScreen;
                    callWinEvent_ev0_ty7_aq0(width, height, displayBitness);
                    return *pstatus = 0, pstatus;
                }
                HDC hDc;
                if (g_primarySurf.dd_surf.dd_surface->GetDC(&hDc) >= 0) {
                    GetSystemPaletteEntries(hDc, 0, 0x100u, g_paletteEntries);
                    g_primarySurf.dd_surf.dd_surface->ReleaseDC(hDc);
                }
            }
            if (displayBitness == 8)
                g_primarySurf.dd_surf.dd_surface->SetPalette(g_lpDDPalette);

            MyDdSurface_constructor(&g_primarySurf.dd_surf, width, height, displayBitness, initFlags);
            MyDdSurface_constructor(&g_offScreen.dd_surf, width, height, displayBitness, initFlags);
            g_pCurOffScreen = &g_offScreen;
            callWinEvent_ev0_ty7_aq0(width, height, displayBitness);
            return *pstatus = 0, pstatus;
        }
        g_primarySurf.dd_surf.dd_surface->Release();
        g_primarySurf.dd_surf.dd_surface = NULL;
        if (displayBitness == 8) {
            g_lpDDPalette->Release();
            g_lpDDPalette = NULL;
        }
        ge_dk2dd_destroy();
        return *pstatus = hres_3, pstatus;
    }

    void ge_ddReleaseSurfaces() {
        FPUControlWordWithState_instance.initialized = 0;
        FPUControlWordWithState_instance.ctl.reset();
        g_isNeedBlt = 0;
        g_ignore_79D3E0 = 0;
        if (!g_primarySurf.dd_surf.dd_surface) return;
        callWinEvent_ev0_ty5(0);
        if (g_dk2dd)
            g_dk2dd->SetCooperativeLevel(g_hWnd, DDSCL_NORMAL);
        if (g_offScreen.dd_surf.dd_surface) {
            if (!patch::opengl_patch::enabled) {
                g_offScreen.dd_surf.dd_surface->Release();
                g_offScreen.dd_surf.dd_surface = NULL;
            } else {
                patch::opengl_patch::releaseOglTexture(g_offScreen.dd_surf.dd_surface);
            }
        }
        if (Obj79D1C0_instance.pPrimaryAttachedSurf) {
            Obj79D1C0_instance.pPrimaryAttachedSurf->Release();
            Obj79D1C0_instance.pPrimaryAttachedSurf = NULL;
        }
        if (g_primarySurf.dd_surf.dd_surface) {
            if (!patch::opengl_patch::enabled) {
                g_primarySurf.dd_surf.dd_surface->Release();
                g_primarySurf.dd_surf.dd_surface = NULL;
            } else {
                patch::opengl_patch::releaseOglTexture(g_primarySurf.dd_surf.dd_surface);
            }
        }
        g_lpDDPalette = NULL;
        if (g_lpDDClipper) {
            g_lpDDClipper->Release();
            g_lpDDClipper = NULL;
        }
    }

}

namespace dk2 {

    LPDIRECTDRAW g_dk2dd = NULL;

    LPDIRECTDRAW __cdecl ge_dk2dd_get(bool addRef) {
        if (!addRef) return g_dk2dd;
        if (!g_dk2dd) return NULL;
        g_dk2dd->AddRef();
        return g_dk2dd;
    }

    void ge_dk2dd_destroy() {
        if (!g_dk2dd) return;
        g_dk2dd->RestoreDisplayMode();
        g_dk2dd->Release();
        g_dk2dd = NULL;
        setSurfaceDD(NULL);
    }

}


int *__cdecl dk2::MyDdSurface_createOffScreenSurface(int *pstatus, uint32_t dwWidth, uint32_t dwHeight, uint32_t dxCaps, MyDdSurface *surf) {
    if(patch::opengl_patch::enabled) {
        patch::log::err("should not happen");
        throw std::exception("should not happen");
        return *pstatus = 0, pstatus;
    }

    DDSURFACEDESC surface_desc;
    static_assert(sizeof(DDSURFACEDESC) == 108);
    surface_desc.dwSize = sizeof(DDSURFACEDESC);
    surface_desc.dwFlags = DDSD_CAPS | DDSD_WIDTH | DDSD_HEIGHT;
    surface_desc.ddsCaps.dwCaps = dxCaps | DDSCAPS_OFFSCREENPLAIN;
    surface_desc.dwHeight = dwHeight;
    surface_desc.dwWidth = dwWidth;
    if (ge_lpSurfaceDD->CreateSurface(&surface_desc, &surf->dd_surface, NULL) != DD_OK)
        return *pstatus = -1, pstatus;

    memset(&surface_desc, 0, sizeof(surface_desc));
    surface_desc.dwSize = sizeof(DDSURFACEDESC);
    surface_desc.dwFlags = DDSD_PIXELFORMAT | DDSD_PITCH | DDSD_CAPS;
    surf->dd_surface->GetSurfaceDesc(&surface_desc);
    MyDdSurface_constructor(surf, dwWidth, dwHeight, surface_desc.ddpfPixelFormat.dwRGBBitCount, 0);
    return *pstatus = 0, pstatus;
}

void __cdecl dk2::CurOffScreen_clearWithPalette0(Bgraf bgraf) {
    int status;
    copyToFullscreenSurf(&status, 0);
    MyDdSurfaceEx_fillWithColor(&status, g_pCurOffScreen, NULL, bgraf, 0);
}

dk2::MySurface *dk2::MyDdSurfaceEx::updateDesc() {
    DDSURFACEDESC desc;
    static_assert(sizeof(DDSURFACEDESC) == 108);
    desc.dwSize = sizeof(DDSURFACEDESC);
    if(patch::opengl_patch::enabled) {
        patch::opengl_patch::getDesc(*this, desc);
        this->fillDesc(&desc);
    } else {
        if (this->dd_surf.dd_surface->GetSurfaceDesc(&desc) >= 0) {
            if (!desc.lpSurface)
                desc.lpSurface = this->surf.lpSurface;
            this->fillDesc(&desc);
        }
    }
    return &this->surf;
}

void dk2::MyDdSurfaceEx::fillDesc(LPDDSURFACEDESC desc) {
    this->surf.lpSurface = desc->lpSurface;
    this->surf.size.w = desc->dwWidth;
    this->surf.size.h = desc->dwHeight;
    this->surf.lPitch = desc->lPitch;
    DWORD dwRGBBitCount = desc->ddpfPixelFormat.dwRGBBitCount;
    if ( dwRGBBitCount == 8 ) {
        this->surf.desc.dwRGBBitCount = 8;
        this->surf.desc.isBytePerPixel = 1;
    } else {
        this->surf.desc.dwRGBBitCount = dwRGBBitCount;
        this->surf.desc.isBytePerPixel = 0;
        this->surf.desc.dwRBitMask = desc->ddpfPixelFormat.dwRBitMask;
        this->surf.desc.dwGBitMask = desc->ddpfPixelFormat.dwGBitMask;
        this->surf.desc.dwBBitMask = desc->ddpfPixelFormat.dwBBitMask;
        this->surf.desc.dwRGBAlphaBitMask = desc->ddpfPixelFormat.dwRGBAlphaBitMask;
    }
}

int *__cdecl dk2::loadArtToSurfaceEx(
        int *pstatus,
        MyDdSurfaceEx *a2_outSurf,
        MyDir_CFileManager *fileMan,
        const char *Str,
        unsigned __int16 a5_extFlags) {
    int status;
    MySurface mySurface;
    mySurface.constructor_empty();

    char myFileBuf[sizeof(MyFile)];
    MyFile &myFile = *(MyFile *) myFileBuf;
    myFile.constructor_empty();

    int try_level = 0;
    TbGraphicFileLoader *imageLoader = MyFile_openImage(&myFile, fileMan, Str, a5_extFlags);
    if (!imageLoader || *imageLoader->readHeader((int *) &a5_extFlags, &myFile, &mySurface) < 0) {
        try_level = -1;
        myFile.destructor();
        return *pstatus = -1, pstatus;
    }
    if (patch::opengl_patch::enabled) {
        patch::opengl_patch::createOglTexture(*a2_outSurf, mySurface, false);
    } else {
        if (*MyDdSurface_createOffScreenSurface(
                &status,
                mySurface.size.w, mySurface.size.h,
                DDSCAPS_SYSTEMMEMORY, &a2_outSurf->dd_surf
        ) < 0) {
            const char *v6 = fileMan->v_getPath();
            sprintf(g_errorBuffer, "LoadArtToSurface failed on CreateSurface!! (%s%s)", v6, Str);
            try_level = -1;
            myFile.destructor();
            return *pstatus = -1, pstatus;
        }
    }
    if (*MyDdSurfaceEx_lock(&status, a2_outSurf, 0) < 0) {
        const char *v8 = fileMan->v_getPath();
        sprintf(g_errorBuffer, "Failed to lock surface for load of '%s%s'", v8, Str);
        MyDdSurface_release((int *) &a5_extFlags, &a2_outSurf->dd_surf);
        try_level = -1;
        myFile.destructor();
        return *pstatus = -1, pstatus;
    }
    MySurface_copyFromSurf(&mySurface, a2_outSurf);
    if (*imageLoader->readBody(&status, &mySurface, &myFile, 0) < 0) {
        if(!patch::opengl_patch::enabled) {
            MyDdSurfaceEx_unlock(a2_outSurf);
            MyDdSurface_release(&status, &a2_outSurf->dd_surf);
        }
        try_level = -1;
        myFile.destructor();
        return *pstatus = -1, pstatus;
    }
    if(!patch::opengl_patch::enabled) {
        MyDdSurfaceEx_unlock(a2_outSurf);
    }
    try_level = -1;
    myFile.destructor();
    return *pstatus = 0, pstatus;
}
