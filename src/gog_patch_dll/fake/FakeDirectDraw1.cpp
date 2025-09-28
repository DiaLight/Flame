//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeDirectDraw1.h>
#include <fake/FakeDirectDraw2.h>
#include <fake/FakeDirectDraw4.h>
#include <fake/FakeD3D.h>
#include <fake/FakeD3D2.h>
#include <fake/FakeZBuffer.h>
#include <fake/FakeSurface.h>
#include <gog_cfg.h>
#include <gog_globals.h>
#include <gog_fake.h>
#include <gog_debug.h>

using namespace gog;

FakeDirectDraw1 *FakeDirectDraw1::instance = nullptr;

HRESULT FakeDirectDraw1::QueryInterface(REFIID riid, LPVOID FAR *ppvObj) {
    if (IsEqualGUID(IID_IDirectDraw2, riid)) {
        *ppvObj = FakeDirectDraw2::instance;
        return DD_OK;
    }
    if (IsEqualGUID(IID_IDirectDraw4, riid)) {
        *ppvObj = FakeDirectDraw4::instance;
        return DD_OK;
    }
    if (IsEqualGUID(IID_IDirect3D, riid)) {
        *ppvObj = FakeD3D::instance;
        return DD_OK;
    }
    if (IsEqualGUID(IID_IDirect3D2, riid)) {
        *ppvObj = FakeD3D2::instance;
        return DD_OK;
    }
    gog_unused_function_called("FakeDirectDraw1::QueryInterface");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw1::Compact(void) {
    gog_unused_function_called("FakeDirectDraw1::Compact");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw1::CreateClipper(DWORD a1, LPDIRECTDRAWCLIPPER *a2, IUnknown *a3) {
    gog_unused_function_called("FakeDirectDraw1::CreateClipper");
//    return DDERR_GENERIC;
    return orig::pIDirectDraw4->CreateClipper(a1, a2, a3);
}

HRESULT FakeDirectDraw1::CreatePalette(DWORD, LPPALETTEENTRY, LPDIRECTDRAWPALETTE *, IUnknown *) {
    gog_unused_function_called("FakeDirectDraw1::CreatePalette");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw1::CreateSurface(LPDDSURFACEDESC pDesc, LPDIRECTDRAWSURFACE *ppSurf, IUnknown *a4) {
    static_assert(0x40 == DDSD_ZBUFFERBITDEPTH);
    if ((pDesc->dwFlags & DDSD_ZBUFFERBITDEPTH) != 0) {
        *ppSurf = FakeZBuffer::instance;
        return DD_OK;
    }
    if (pDesc->ddpfPixelFormat.dwFlags == 4) {
        return DDERR_INVALIDPIXELFORMAT;
    }
    *(LPDIRECTDRAWSURFACE2 *) ppSurf = new FakeSurface((LPDDSURFACEDESC2) pDesc);
    return DD_OK;
}

HRESULT FakeDirectDraw1::DuplicateSurface(LPDIRECTDRAWSURFACE, LPDIRECTDRAWSURFACE *) {
    gog_unused_function_called("FakeDirectDraw1::DuplicateSurface");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw1::EnumDisplayModes(DWORD, LPDDSURFACEDESC pDesc, LPVOID a4, LPDDENUMMODESCALLBACK cb) {
    if (pDesc) gog_assert_failed("FakeDirectDraw1::EnumDisplayModes:1289");
    DDSURFACEDESC desc;
    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(DDSURFACEDESC);
    static_assert(sizeof(DDSURFACEDESC) == 108);
    desc.ddpfPixelFormat.dwSize = 32;
    desc.dwFlags = 0x1006;
    desc.ddpfPixelFormat.dwFlags = 0x40;
    desc.ddpfPixelFormat.dwRGBBitCount = 32;
    desc.ddpfPixelFormat.dwBBitMask = 0xFF;
    desc.ddpfPixelFormat.dwGBitMask = 0xFF00;
    desc.ddpfPixelFormat.dwRBitMask = 0xFF0000;
    desc.dwWidth = 640;
    desc.dwHeight = 480;
    cb(&desc, a4);
    desc.dwWidth = 800;
    desc.dwHeight = 600;
    cb(&desc, a4);
    desc.dwWidth = 1024;
    desc.dwHeight = 768;
    cb(&desc, a4);
    if (cfg::iHighRes) {
        desc.dwWidth = 1280;
        desc.dwHeight = 1024;
        cb(&desc, a4);
        desc.dwWidth = 1600;
        desc.dwHeight = 1200;
        cb(&desc, a4);
    }
    HKEY phkResult;
    LSTATUS iResult;
    iResult = RegOpenKeyExA(
            HKEY_CURRENT_USER,
            "Software\\Bullfrog Productions Ltd\\Dungeon Keeper II\\Configuration\\Video",
            0, 1u, &phkResult);
    if (iResult != ERROR_SUCCESS) {
        return DD_OK;
    }
    DWORD size;
    size = 4;
    DWORD width = 0;
    iResult = RegQueryValueExA(phkResult, "Screen Width", NULL, 0, (LPBYTE) &width, (LPDWORD) &size);
    if (iResult != ERROR_SUCCESS || width == 0)
        return DD_OK;
    size = 4;
    DWORD height = 0;
    iResult = RegQueryValueExA(phkResult, "Screen Height", NULL, 0, (LPBYTE) &height, (LPDWORD) &size);
    if (iResult != ERROR_SUCCESS || height == 0)
        return DD_OK;
    if (width == 640 && height == 480) return DD_OK;
    if (width == 800 && height == 600) return DD_OK;
    if (width == 1024 && height == 768) return DD_OK;
    if (cfg::iHighRes) {
        if (width == 1280 && height == 1024) return DD_OK;
        if (width == 1600 && height == 1200) return DD_OK;
    }
    desc.dwHeight = height;
    desc.dwWidth = width;
    cb(&desc, a4);
    return DD_OK;
}

HRESULT FakeDirectDraw1::EnumSurfaces(DWORD, LPDDSURFACEDESC, LPVOID, LPDDENUMSURFACESCALLBACK) {
    gog_unused_function_called("FakeDirectDraw1::EnumSurfaces");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw1::FlipToGDISurface(void) {
    gog_unused_function_called("FakeDirectDraw1::FlipToGDISurface");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw1::GetCaps(LPDDCAPS hwCaps, LPDDCAPS halCaps) {
    if (!hwCaps) gog_assert_failed("FakeDirectDraw1::GetCaps:1370");
    if (halCaps) gog_assert_failed("FakeDirectDraw1::GetCaps:1371");
    DDCAPS caps;
    caps.dwSize = sizeof(DDCAPS);
    static_assert(sizeof(DDCAPS) == 380);
    caps.dwCaps = 0x95C07FC1;
    caps.dwCaps2 = 0x806AB230;
    caps.dwCKeyCaps = 0x311;
    caps.dwFXCaps = 0x22AD5420;
    memset(&caps.dwFXAlphaCaps, 0, 0x29);
    caps.dwVidMemTotal = 0xAF42C000;
    caps.dwVidMemFree = 0xAEF2C000;
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
    memcpy(hwCaps, &caps, hwCaps->dwSize);
    return DD_OK;
}

HRESULT FakeDirectDraw1::GetDisplayMode(LPDDSURFACEDESC desc) {
    gog_unused_function_called("FakeDirectDraw1::GetDisplayMode");
//    return DDERR_GENERIC;
    return orig::pIDirectDraw4->GetDisplayMode((LPDDSURFACEDESC2) desc);
}

HRESULT FakeDirectDraw1::GetFourCCCodes(LPDWORD, LPDWORD) {
    gog_unused_function_called("FakeDirectDraw1::GetFourCCCodes");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw1::GetGDISurface(LPDIRECTDRAWSURFACE *) {
    gog_unused_function_called("FakeDirectDraw1::GetGDISurface");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw1::GetMonitorFrequency(LPDWORD) {
    gog_unused_function_called("FakeDirectDraw1::GetMonitorFrequency");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw1::GetScanLine(LPDWORD) {
    gog_unused_function_called("FakeDirectDraw1::GetScanLine");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw1::GetVerticalBlankStatus(LPBOOL) {
    gog_unused_function_called("FakeDirectDraw1::GetVerticalBlankStatus");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw1::Initialize(GUID *) {
    gog_unused_function_called("FakeDirectDraw1::Initialize");
    return DDERR_GENERIC;
}

HRESULT FakeDirectDraw1::RestoreDisplayMode(void) {
    return DD_OK;
}

HRESULT FakeDirectDraw1::SetCooperativeLevel(HWND hwnd, DWORD a3) {
    if (!hwnd)
        return DD_OK;
    if (gog::g_hWnd) {
        if (gog::g_hWnd != hwnd) {
            gog_assert_failed("FakeDirectDraw1::SetCooperativeLevel:1436");
            return DD_OK;
        }
        return DD_OK;
    }
    gog::g_hWnd = hwnd;
    HRESULT hr;
    if (cfg::iRealFullscreen)
        hr = orig::pIDirectDraw4->SetCooperativeLevel(hwnd, 0x11);
    else
        hr = orig::pIDirectDraw4->SetCooperativeLevel(hwnd, 0x8);
    if (FAILED(hr)) {
        gog_assert_failed_hr("FakeDirectDraw1::SetCooperativeLevel:1445", hr);
        return hr;
    }
    DDSURFACEDESC2 surfDesc;
    memset(&surfDesc, 0, sizeof(surfDesc));
    surfDesc.dwSize = 124;
    static_assert(sizeof(DDSURFACEDESC2) == 124);
    surfDesc.dwFlags = 1;
    surfDesc.ddsCaps.dwCaps = 0x200;
    hr = orig::pIDirectDraw4->CreateSurface(&surfDesc, &orig::pIDirectDrawSurface4_coop, 0);
    if (FAILED(hr)) {
        gog_assert_failed_hr("FakeDirectDraw1::SetCooperativeLevel:1451", hr);
    }
    hr = orig::pIDirectDraw4->QueryInterface(IID_IDirect3D3, (LPVOID *) &orig::pIDirect3D3);
    if (FAILED(hr)) {
        gog_assert_failed_hr("FakeDirectDraw1::SetCooperativeLevel:1453", hr);
    }
    if (!gog::g_isAntialiasGt10) return DD_OK;
    memset(&surfDesc, 0, sizeof(surfDesc));
    surfDesc.dwSize = 124;
    static_assert(sizeof(DDSURFACEDESC2) == 124);
    surfDesc.ddpfPixelFormat.dwSize = sizeof(DDPIXELFORMAT);
    static_assert(sizeof(DDPIXELFORMAT) == 32);
    surfDesc.ddpfPixelFormat.dwFlags = 0x40;
    surfDesc.ddpfPixelFormat.dwRGBBitCount = 32;
    surfDesc.ddpfPixelFormat.dwRBitMask = 0xFF0000;
    surfDesc.ddpfPixelFormat.dwGBitMask = 0xFF00;
    surfDesc.ddpfPixelFormat.dwBBitMask = 0xFF;
    surfDesc.dwFlags = 0x1007;
    surfDesc.ddsCaps.dwCaps = 0x4040;
    surfDesc.dwWidth = 640;
    surfDesc.dwHeight = 480;
    hr = orig::pIDirectDraw4->CreateSurface(&surfDesc, &orig::pIDirectDrawSurface4_640x480, NULL);
    if (FAILED(hr)) {
        gog_assert_failed_hr("FakeDirectDraw1::SetCooperativeLevel:1474", hr);
    }
    return DD_OK;
}

HRESULT FakeDirectDraw1::SetDisplayMode(DWORD width, DWORD height, DWORD a4) {
    if (FakeSurface::instance_mod) {
        FakeSurface::instance_mod->Release();
        FakeSurface::instance_mod = nullptr;
    }
    if (FakeSurface::instance_cpy) {
        FakeSurface::instance_cpy->Release();
        FakeSurface::instance_cpy = nullptr;
    }
    if (orig::pIDirectDrawSurface4_zbuf) {
        orig::pIDirectDrawSurface4_zbuf->Release();
        orig::pIDirectDrawSurface4_zbuf = nullptr;
    }
    g_dwWidth = width;
    g_dwHeight = height;
    if (a4 != 32) gog_assert_failed("FakeDirectDraw1::SetDisplayMode:1488");
    if (cfg::iNotOnTop)
        SetWindowPos(g_hWnd, (HWND) 0xFFFFFFFE, 0, 0, 0, 0, 3u);
    gog_debugf("Screen mode set: %dx%d", width, height);
    Fake_InitRenderRect();
    if (!orig::pIDirectDrawSurface4_coop)
        return DD_OK;
    DDBLTFX bitblt;
    memset(&bitblt, 0, sizeof(bitblt));
    bitblt.dwSize = 100;
    orig::pIDirectDrawSurface4_coop->Blt(NULL, NULL, NULL, 1024, &bitblt);
    return DD_OK;
}

HRESULT FakeDirectDraw1::WaitForVerticalBlank(DWORD, HANDLE) {
    gog_unused_function_called("FakeDirectDraw1::WaitForVerticalBlank");
    return DDERR_GENERIC;
}


