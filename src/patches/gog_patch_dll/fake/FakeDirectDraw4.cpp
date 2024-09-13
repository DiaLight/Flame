//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeDirectDraw4.h>
#include <fake/FakeD3D3.h>
#include <fake/FakeSurface4.h>
#include <gog_debug.h>

using namespace gog;

FakeDirectDraw4 *FakeDirectDraw4::instance = nullptr;

HRESULT FakeDirectDraw4::QueryInterface(REFIID riid, LPVOID FAR *ppvObj) {
    if (IsEqualGUID(IID_IDirect3D3, riid)) {
        *ppvObj = FakeD3D3::instance;
        return DD_OK;
    }
    gog_debug("Unused function called: FakeDirectDraw4::QueryInterface");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::Compact(void) {
    gog_debug("Unused function called: FakeDirectDraw4::Compact");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::CreateClipper(DWORD, LPDIRECTDRAWCLIPPER *, IUnknown *) {
    gog_debug("Unused function called: FakeDirectDraw4::CreateClipper");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::CreatePalette(DWORD, LPPALETTEENTRY, LPDIRECTDRAWPALETTE *, IUnknown *) {
    gog_debug("Unused function called: FakeDirectDraw4::CreatePalette");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::CreateSurface(LPDDSURFACEDESC2 pDesc, LPDIRECTDRAWSURFACE4 *ppSurf, IUnknown *a4) {
    if (!pDesc) gog_debug("Assertion failed: FakeDirectDraw4::CreateSurface:1053");
    if (a4) gog_debug("Assertion failed: FakeDirectDraw4::CreateSurface:1054");
    auto *surf = new FakeSurface4(pDesc);
    if (!surf->orig()) gog_debug("Assertion failed: FakeDirectDraw4::CreateSurface:1056");
    *ppSurf = surf;
    return DD_OK;
}

HRESULT FakeDirectDraw4::DuplicateSurface(LPDIRECTDRAWSURFACE4, LPDIRECTDRAWSURFACE4 *) {
    gog_debug("Unused function called: FakeDirectDraw4::DuplicateSurface");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::EnumDisplayModes(DWORD, LPDDSURFACEDESC2, LPVOID, LPDDENUMMODESCALLBACK2) {
    gog_debug("Unused function called: FakeDirectDraw4::EnumDisplayModes");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::EnumSurfaces(DWORD, LPDDSURFACEDESC2, LPVOID, LPDDENUMSURFACESCALLBACK2) {
    gog_debug("Unused function called: FakeDirectDraw4::EnumSurfaces");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::FlipToGDISurface(void) {
    gog_debug("Unused function called: FakeDirectDraw4::FlipToGDISurface");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::GetCaps(LPDDCAPS hwCaps, LPDDCAPS halCaps) {
    if (!hwCaps) gog_debug("Assertion failed: FakeDirectDraw4::GetCaps:1065");
    if (halCaps) gog_debug("Assertion failed: FakeDirectDraw4::GetCaps:1066");
    DDCAPS hwCaps_;
    hwCaps_.dwSize = sizeof(DDCAPS);
    static_assert(sizeof(DDCAPS) == 380);
    hwCaps_.dwCaps = 0x95C07FC1;
    hwCaps_.dwCaps2 = 0x806AB230;
    hwCaps_.dwCKeyCaps = 0x311;
    hwCaps_.dwFXCaps = 0x22AD5420;
    memset(&hwCaps_.dwFXAlphaCaps, 0, 0x29);
    hwCaps_.dwVidMemTotal = 0xAF42C000;
    hwCaps_.dwVidMemFree = 0xAEEC0800;
    hwCaps_.dwMaxVisibleOverlays = 1;
    hwCaps_.dwCurrVisibleOverlays = 0;
    hwCaps_.dwNumFourCCCodes = 21;
    memset(&hwCaps_.dwAlignBoundarySrc, 0, 0x2C);
    hwCaps_.dwRops[6] = 0x1000;
    hwCaps_.dwRops[7] = 0;
    hwCaps_.ddsOldCaps.dwCaps = 0x304672FC;
    hwCaps_.dwMinOverlayStretch = 0x20;
    hwCaps_.dwMaxOverlayStretch = 0x7D000;
    memset(&hwCaps_.dwMinLiveVideoStretch, 0, 0x1C);
    hwCaps_.dwSVBCaps = 0x40;
    memset(&hwCaps_.dwSVBCKeyCaps, 0, 0x20);
    hwCaps_.dwSVBRops[6] = 0x1000;
    hwCaps_.dwSVBRops[7] = 0;
    hwCaps_.dwVSBCaps = 0x40;
    memset(&hwCaps_.dwVSBCKeyCaps, 0, 0x20);
    hwCaps_.dwVSBRops[6] = 0x1000;
    memset(&hwCaps_.dwVSBRops[7], 0, 0x3C);
    hwCaps_.dwNLVBCaps = 0x95C07FC1;
    hwCaps_.dwNLVBCaps2 = 0x8062B230;
    hwCaps_.dwNLVBCKeyCaps = 0x311;
    hwCaps_.dwNLVBFXCaps = 0x22AD5420;
    memset(hwCaps_.dwNLVBRops, 0, 0x18);
    hwCaps_.dwNLVBRops[6] = 0x1000;
    hwCaps_.dwNLVBRops[7] = 0;
    hwCaps_.ddsCaps.dwCaps = 0x304672FC;
    hwCaps_.ddsCaps.dwCaps2 = 0x200;
    hwCaps_.ddsCaps.dwCaps3 = 0;
    hwCaps_.ddsCaps.dwCaps4 = 0;
    DWORD dwSize = hwCaps->dwSize;
    memcpy(hwCaps, &hwCaps_, dwSize);
    return DD_OK;
}

HRESULT FakeDirectDraw4::GetDisplayMode(LPDDSURFACEDESC2) {
    gog_debug("Unused function called: FakeDirectDraw4::GetDisplayMode");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::GetFourCCCodes(LPDWORD, LPDWORD) {
    gog_debug("Unused function called: FakeDirectDraw4::GetFourCCCodes");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::GetGDISurface(LPDIRECTDRAWSURFACE4 *) {
    gog_debug("Unused function called: FakeDirectDraw4::GetGDISurface");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::GetMonitorFrequency(LPDWORD) {
    gog_debug("Unused function called: FakeDirectDraw4::GetMonitorFrequency");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::GetScanLine(LPDWORD) {
    gog_debug("Unused function called: FakeDirectDraw4::GetScanLine");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::GetVerticalBlankStatus(LPBOOL) {
    gog_debug("Unused function called: FakeDirectDraw4::GetVerticalBlankStatus");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::Initialize(GUID *) {
    gog_debug("Unused function called: FakeDirectDraw4::Initialize");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::RestoreDisplayMode(void) {
    gog_debug("Unused function called: FakeDirectDraw4::RestoreDisplayMode");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::SetCooperativeLevel(HWND, DWORD) {
    gog_debug("Unused function called: FakeDirectDraw4::SetCooperativeLevel");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::SetDisplayMode(DWORD, DWORD, DWORD, DWORD, DWORD) {
    gog_debug("Unused function called: FakeDirectDraw4::SetDisplayMode");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::WaitForVerticalBlank(DWORD, HANDLE) {
    gog_debug("Unused function called: FakeDirectDraw4::WaitForVerticalBlank");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::GetAvailableVidMem(LPDDSCAPS2, LPDWORD, LPDWORD) {
    gog_debug("Unused function called: FakeDirectDraw4::GetAvailableVidMem");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::GetSurfaceFromDC(HDC, LPDIRECTDRAWSURFACE4 *) {
    gog_debug("Unused function called: FakeDirectDraw4::GetSurfaceFromDC");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::RestoreAllSurfaces(void) {
    gog_debug("Unused function called: FakeDirectDraw4::RestoreAllSurfaces");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::TestCooperativeLevel(void) {
    gog_debug("Unused function called: FakeDirectDraw4::TestCooperativeLevel");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw4::GetDeviceIdentifier(LPDDDEVICEIDENTIFIER pDevId, DWORD) {
    DDDEVICEIDENTIFIER devId;
    if (!pDevId) gog_debug("Assertion failed: FakeDirectDraw4::GetDeviceIdentifier:1126");
    memset(&devId, 0, sizeof(devId));
    devId.guidDeviceIdentifier = IID_IDirectDraw7;
    strcpy_s(devId.szDriver, 0x200u, "RandomFakeDriver");
    strcpy_s(devId.szDescription, 0x200u, "DX6 compatibility layer");
    memcpy(pDevId, &devId, sizeof(tagDDDEVICEIDENTIFIER));
    return 0;
}


