//
// Created by DiaLight on 12.09.2024.
//
#include <Windows.h>
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/DxDeviceInfo.h"
#include "dk2/DxD3dInfo.h"
#include "gog_patch.h"
#include "gog_exports.h"


BOOL dk2::collect_devices_DDEnumCB(GUID *lpGUID, const CHAR *driverName, const CHAR *driverDesc, LPVOID a4) {
    int device_idx = ddraw_device_count;
    DxDeviceInfo *devs;
    if ( ddraw_device_count ) {
        static_assert(sizeof(DxDeviceInfo) == 0x21A);
        devs = (DxDeviceInfo *) dk2::_realloc(ddraw_devices, sizeof(DxDeviceInfo) * (ddraw_device_count + 1));
    } else {
        devs = (DxDeviceInfo *)_malloc_1(538u);
    }
    ddraw_devices = devs;
    int device_offs = device_idx;
    if (lpGUID) {
        devs[device_idx].pGuid = &devs[device_idx].guid;
        ddraw_devices[device_idx].guid = *lpGUID;
    } else {
        devs[device_idx].pGuid = NULL;
    }
    lstrcpyA(ddraw_devices[device_offs].desc, driverName);
    lstrcpyA(ddraw_devices[device_offs].name, driverDesc);
    ddraw_devices[device_offs].modeListCount = 0;
    ddraw_devices[device_offs].modeList = NULL;
    ddraw_devices[device_offs].infoListCount = 0;
    ddraw_devices[device_offs].infoList = NULL;

    LPDIRECTDRAW lpDD;
    if(*o_gog_enabled) {
        fake_DirectDrawCreate(lpGUID, &lpDD, NULL);
    } else {
        DirectDrawCreate(lpGUID, &lpDD, NULL);
    }

    static_assert(sizeof(DDCAPS_DX7) == 380);
    ddraw_devices->ddcaps.dwSize = sizeof(DDCAPS_DX7);
    lpDD->GetCaps(&ddraw_devices->ddcaps, NULL);

    DxDeviceInfo *ddraw_device = &ddraw_devices[device_offs];
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
    ddraw_devices[device_offs].isVendor121A = 0;
    if ( ddraw_devices[device_offs].dwVendorId == 0x121A ) {
        int f212_dwDeviceId = ddraw_devices[device_offs].dwDeviceId;
        if ( f212_dwDeviceId == 1 || f212_dwDeviceId == 2 ) {
            ddraw_devices[device_offs].isVendor121A = 1;
        }
    }
    IDirect3D *d3d;
    lpDD->QueryInterface(CLSID_IDirect3D, (LPVOID *)&d3d);
    d3d->EnumDevices((LPD3DENUMDEVICESCALLBACK)collect_devices_DDEnumDevicesCB, (LPVOID)device_idx);
    d3d->Release();
    lpDD->Release();
    ++ddraw_device_count;
    return 1;
}

BOOL dk2::collect_displayModes_DDEnumCB(GUID *lpGUID, LPSTR a2, LPSTR a3, HWND hWindow) {
    LPDIRECTDRAW lpDD;
    if(*o_gog_enabled) {
        fake_DirectDrawCreate(lpGUID, &lpDD, NULL);
    } else {
        DirectDrawCreate(lpGUID, &lpDD, NULL);
    }
    lpDD->SetCooperativeLevel(hWindow, 21);
    ddraw_devices[dd_index].modeListCount = 0;
    lpDD->EnumDisplayModes(0, NULL, (void *)dd_index, (LPDDENUMMODESCALLBACK)collect_displayModes_DDEnumModesCB);
    lpDD->SetCooperativeLevel(hWindow, 8);
    lpDD->Release();
    ++dd_index;
    return 1;
}

int *__cdecl dk2::createDirectDrawObject(int *pstatus, GUID *lpGUID, LPDIRECTDRAW *lplpDD) {
    HRESULT hresult;
    if(*o_gog_enabled) {
        hresult = fake_DirectDrawCreate(lpGUID, lplpDD, NULL);
    } else {
        hresult = DirectDrawCreate(lpGUID, lplpDD, NULL);
    }
    if (hresult != DD_OK) {
        *pstatus = -1;
        return pstatus;
    }
    if (g_hBullfrogWindow) setHWindow(g_hBullfrogWindow);
    *pstatus = 0;
    return pstatus;
}


int dk2::getDevIdxSupportsLinearPerspective() {
    int devCount = ddraw_device_count;
    if (ddraw_device_count == 0) {
        if(*o_gog_enabled) {
            fake_DirectDrawEnumerateA((LPDDENUMCALLBACKA) collect_devices_DDEnumCB, NULL);
        } else {
            DirectDrawEnumerateA((LPDDENUMCALLBACKA) collect_devices_DDEnumCB, NULL);
        }
        devCount = ddraw_device_count;
    }
    static_assert(sizeof(DxDeviceInfo) == 0x21A);
    for (int i = 0; i < devCount; ++i) {
        DxD3dInfo *d3dInfo = ddraw_devices[i].infoList;
        if (!d3dInfo) continue;
        if (!d3dInfo->hasDesc) continue;
        if (!d3dInfo->texCapsAnd1) continue;
        if (!d3dInfo->hasZbuffer) continue;
        D3DDEVICEDESC devDesc = d3dInfo->devDesc;
        if ((devDesc.dpcTriCaps.dwTextureCaps & 1) == 0) continue;
        if ((devDesc.dpcTriCaps.dwTextureFilterCaps & 2) == 0) continue;
        return i;
    }
    return -1;
}


namespace dk2 {
    void inline_selectDrawEngine(dk2::MyGame *game) {
        game->dds_count = 0;
        if(*o_gog_enabled) {
            fake_DirectDrawEnumerateA((LPDDENUMCALLBACKA) collect_namesAndDescs_DDEnumCB, game);
            if (ddraw_device_count == 0)
                fake_DirectDrawEnumerateA((LPDDENUMCALLBACKA) collect_devices_DDEnumCB, NULL);
            if (dd_index == 0)
                fake_DirectDrawEnumerateA((LPDDENUMCALLBACKA) collect_displayModes_DDEnumCB, getHWindow());
        } else {
            DirectDrawEnumerateA((LPDDENUMCALLBACKA) collect_namesAndDescs_DDEnumCB, game);
            if (ddraw_device_count == 0)
                DirectDrawEnumerateA((LPDDENUMCALLBACKA) collect_devices_DDEnumCB, NULL);
            if (dd_index == 0)
                DirectDrawEnumerateA((LPDDENUMCALLBACKA) collect_displayModes_DDEnumCB, getHWindow());
        }
        int selectedDdIdx = -1;
        if (!MyResources_instance.video_settings.cmd_flag_SOFTWARE) {
            if (cmd_flag_DDD) {
                game->selected_dd_idx = cmd_flag_DDD_value;
                return;
            }
            int devCount = ddraw_device_count;
            if (MyResources_instance.video_settings.guid_index < ddraw_device_count
                && MyResources_instance.video_settings.guid_index_verifier_working) {
                game->selected_dd_idx = MyResources_instance.video_settings.guid_index;
                return;
            }
            if (!ddraw_device_count) {
                if(*o_gog_enabled) {
                    fake_DirectDrawEnumerateA((LPDDENUMCALLBACKA) collect_devices_DDEnumCB, 0);
                } else {
                    DirectDrawEnumerateA((LPDDENUMCALLBACKA) collect_devices_DDEnumCB, 0);
                }
                devCount = ddraw_device_count;
            }
            if (devCount > 0) {
                for (int i = 0; i < ddraw_device_count; ++i) {
                    if(isDevSupports_D3DPTFILTERCAPS_LINEARMIPNEAREST(i)) {
                        selectedDdIdx = i;
                        break;
                    }
                }
            }
        }
        if (selectedDdIdx < 0) {
            // software render engine
            MyResources_instance.video_settings.setSelected3dEngine(4);
            MyResources_instance.video_settings.writeGuidIndex(0);
            game->selected_dd_idx = 0;
        } else {
            MyResources_instance.video_settings.setSelected3dEngine(2);
            MyResources_instance.video_settings.writeGuidIndex(selectedDdIdx);
            game->selected_dd_idx = selectedDdIdx;
        }
    }
}
