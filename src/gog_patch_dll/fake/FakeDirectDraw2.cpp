//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeDirectDraw2.h>
#include <gog_globals.h>
#include <gog_cfg.h>
#include <fake/FakeSurface.h>
#include <gog_debug.h>

using namespace gog;

FakeDirectDraw2 *FakeDirectDraw2::instance = nullptr;

HRESULT FakeDirectDraw2::QueryInterface(REFIID riid, LPVOID FAR *ppvObj) {
    gog_debug("Unused function called: FakeDirectDraw2::QueryInterface");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::Compact(void) {
    gog_debug("Unused function called: FakeDirectDraw2::Compact");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::CreateClipper(DWORD, LPDIRECTDRAWCLIPPER *, IUnknown *) {
    gog_debug("Unused function called: FakeDirectDraw2::CreateClipper");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::CreatePalette(DWORD, LPPALETTEENTRY, LPDIRECTDRAWPALETTE *, IUnknown *) {
    gog_debug("Unused function called: FakeDirectDraw2::CreatePalette");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::CreateSurface(LPDDSURFACEDESC pDesc, LPDIRECTDRAWSURFACE *ppSurf, IUnknown *a4) {
    if (!gog::g_isMsgSent) {
        if (gog::g_hWnd) {
            g_isMsgSent = true;
            if (cfg::iRestoreMode == 1) {
                SendMessageA(gog::g_hWnd, WM_ACTIVATE, WA_ACTIVE, (LPARAM) (HWND) NULL);
            }
        }
    }
    if (pDesc->ddpfPixelFormat.dwFlags != 4) gog_debug("Assertion failed: FakeDirectDraw2::CreateSurface:1161");
    if (cfg::iDisableFourCC)
        return DDERR_INVALIDPIXELFORMAT;
    *(LPDIRECTDRAWSURFACE2 *) ppSurf = new FakeSurface((LPDDSURFACEDESC2) pDesc);
    return DD_OK;
}

HRESULT FakeDirectDraw2::DuplicateSurface(LPDIRECTDRAWSURFACE, LPDIRECTDRAWSURFACE *) {
    gog_debug("Unused function called: FakeDirectDraw2::DuplicateSurface");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::EnumDisplayModes(DWORD, LPDDSURFACEDESC, LPVOID, LPDDENUMMODESCALLBACK) {
    gog_debug("Unused function called: FakeDirectDraw2::EnumDisplayModes");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::EnumSurfaces(DWORD, LPDDSURFACEDESC, LPVOID, LPDDENUMSURFACESCALLBACK) {
    gog_debug("Unused function called: FakeDirectDraw2::EnumSurfaces");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::FlipToGDISurface(void) {
    gog_debug("Unused function called: FakeDirectDraw2::FlipToGDISurface");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::GetCaps(LPDDCAPS hwCaps, LPDDCAPS halCaps) {
    DDCAPS caps;
    caps.dwSize = sizeof(DDCAPS);
    static_assert(sizeof(DDCAPS) == 380);
    caps.dwCaps = 0x95C07FC1;
    caps.dwCaps2 = 0x806AB230;
    caps.dwCKeyCaps = 0x311;
    caps.dwFXCaps = 0x22AD5420;
    memset(&caps.dwFXAlphaCaps, 0, 0x28);
    caps.dwVidMemTotal = 0xAF42C000;
    caps.dwVidMemFree = 0xAEEC0800;
    caps.dwMaxVisibleOverlays = 1;
    caps.dwCurrVisibleOverlays = 0;
    caps.dwNumFourCCCodes = 21;
    memset(&caps.dwAlignBoundarySrc, 0, 0x2C);
    caps.dwRops[6] = 0x1000;
    caps.dwRops[7] = 0;
    caps.ddsOldCaps.dwCaps = 0x304672FC;
    caps.dwMinOverlayStretch = 0x20;
    caps.dwMaxOverlayStretch = 0x7D000;
    memset(&caps.dwMinLiveVideoStretch, 0, 0x1C);
    caps.dwSVBCaps = 0x40;
    memset(&caps.dwSVBCKeyCaps, 0, 0x20);
    caps.dwSVBRops[6] = 0x1000;
    caps.dwSVBRops[7] = 0;
    caps.dwVSBCaps = 0x40;
    memset(&caps.dwVSBCKeyCaps, 0, 0x20);
    caps.dwVSBRops[6] = 0x1000;
    memset(&caps.dwVSBRops[7], 0, 0x3C);
    caps.dwNLVBCaps = 0x95C07FC1;
    caps.dwNLVBCaps2 = 0x8062B230;
    caps.dwNLVBCKeyCaps = 0x311;
    caps.dwNLVBFXCaps = 0x22AD5420;
    memset(caps.dwNLVBRops, 0, 0x18);
    caps.dwNLVBRops[6] = 0x1000;
    caps.dwNLVBRops[7] = 0;
    caps.ddsCaps.dwCaps = 0x304672FC;
    caps.ddsCaps.dwCaps2 = 0x200;
    caps.ddsCaps.dwCaps3 = 0;
    caps.ddsCaps.dwCaps4 = 0;
    if (hwCaps)
        memcpy(hwCaps, &caps, hwCaps->dwSize);
    if (halCaps)
        memcpy(halCaps, &caps, halCaps->dwSize);
    return DD_OK;
}

HRESULT FakeDirectDraw2::GetDisplayMode(LPDDSURFACEDESC) {
    gog_debug("Unused function called: FakeDirectDraw2::GetDisplayMode");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::GetFourCCCodes(LPDWORD a2, LPDWORD a3) {
    *a2 = 0;
    if (a3)
        *a3 = 0;
    return DD_OK;
}

HRESULT FakeDirectDraw2::GetGDISurface(LPDIRECTDRAWSURFACE *) {
    gog_debug("Unused function called: FakeDirectDraw2::GetGDISurface");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::GetMonitorFrequency(LPDWORD) {
    gog_debug("Unused function called: FakeDirectDraw2::GetMonitorFrequency");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::GetScanLine(LPDWORD) {
    gog_debug("Unused function called: FakeDirectDraw2::GetScanLine");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::GetVerticalBlankStatus(LPBOOL) {
    gog_debug("Unused function called: FakeDirectDraw2::GetVerticalBlankStatus");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::Initialize(GUID *) {
    gog_debug("Unused function called: FakeDirectDraw2::Initialize");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::RestoreDisplayMode(void) {
    gog_debug("Unused function called: FakeDirectDraw2::RestoreDisplayMode");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::SetCooperativeLevel(HWND, DWORD) {
    gog_debug("Unused function called: FakeDirectDraw2::SetCooperativeLevel");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::SetDisplayMode(DWORD, DWORD, DWORD, DWORD, DWORD) {
    gog_debug("Unused function called: FakeDirectDraw2::SetDisplayMode");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::WaitForVerticalBlank(DWORD, HANDLE) {
    gog_debug("Unused function called: FakeDirectDraw2::WaitForVerticalBlank");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw2::GetAvailableVidMem(LPDDSCAPS, LPDWORD a3, LPDWORD a4) {
    if (a3)
        *a3 = 0x2000000;
    if (a4)
        *a4 = 0x2000000;
    return DD_OK;
}


