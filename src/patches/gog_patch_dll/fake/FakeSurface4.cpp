//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeSurface4.h>
#include <gog_globals.h>
#include <fake/FakeGammaControl.h>
#include <fake/FakeTexture.h>
#include <gog_fake.h>
#include <gog_debug.h>

using namespace gog;


FakeSurface4::FakeSurface4(LPDIRECTDRAWSURFACE4 orig_surf, bool isModSurf) {
    this->f8_orig_surf = orig_surf;
    orig_surf->AddRef();
    this->fC_isModSurf = isModSurf;
    this->f10_lockCounter = 0;
    memset(&this->f14_desc, 0, sizeof(this->f14_desc));
    this->f14_desc.dwSize = sizeof(DDSURFACEDESC2);
    static_assert(sizeof(DDSURFACEDESC2) == 124);
    HRESULT hr = this->f8_orig_surf->GetSurfaceDesc(&this->f14_desc);
    if (FAILED(hr)) gog_debug("Assertion failed: FakeSurface4::FakeSurface4:200");
}

FakeSurface4::FakeSurface4(LPDDSURFACEDESC2 pDesc) {
    static_assert(sizeof(DDSURFACEDESC2) == 0x7C);
    DDSURFACEDESC2 desc;
    memcpy(&desc, pDesc, sizeof(desc));
    DWORD dwFlags = desc.dwFlags;
    if ((desc.dwFlags & 1) != 0 && (desc.ddsCaps.dwCaps & 0x200) != 0 && (desc.dwFlags & 4) == 0) {
        gog_debug("Assertion failed: FakeSurface4::FakeSurface4:207");
    } else {
        this->fC_isModSurf = false;
        if ((dwFlags & 0x1000) == 0) gog_debug("Assertion failed: FakeSurface4::FakeSurface4:210");
        if (desc.ddpfPixelFormat.dwRGBBitCount != 32) gog_debug("Assertion failed: FakeSurface4::FakeSurface4:211");
    }
    memcpy(&this->f14_desc, &desc, sizeof(this->f14_desc));
    if ((this->f14_desc.ddsCaps.dwCaps & 0x30000000) != 0) gog_debug(
            "Assertion failed: FakeSurface4::FakeSurface4:216");
    if ((this->f14_desc.ddsCaps.dwCaps & 0x1000) == 0) gog_debug("Assertion failed: FakeSurface4::FakeSurface4:217");
    if ((this->f14_desc.dwFlags & 0x40) != 0) gog_debug("Assertion failed: FakeSurface4::FakeSurface4:218");
    if (!this->f14_desc.dwWidth) gog_debug("Assertion failed: FakeSurface4::FakeSurface4:219");
    if (!this->f14_desc.dwHeight) gog_debug("Assertion failed: FakeSurface4::FakeSurface4:220");
    HRESULT hr = orig::pIDirectDraw4->CreateSurface(&this->f14_desc, &this->f8_orig_surf, NULL);
    if (FAILED(hr)) {
        gog_debugf("Assertion failed: FakeSurface4::FakeSurface4:227 with HRESULT 0x%x", hr);
        if (hr == DDERR_INVALIDCAPS) {
        }
        this->f8_orig_surf = nullptr;
        __debugbreak();
    }
}

HRESULT FakeSurface4::QueryInterface(REFIID riid, LPVOID FAR *ppvObj) {
    if (IsEqualGUID(IID_IDirectDrawGammaControl, riid)) {
        *ppvObj = FakeGammaControl::instance;
        return DD_OK;
    }
    if (IsEqualGUID(IID_IDirect3DTexture2, riid)) {
        IDirect3DTexture2 *orig_tex;
        HRESULT hr = this->f8_orig_surf->QueryInterface(IID_IDirect3DTexture2, (LPVOID *) &orig_tex);
        if (SUCCEEDED(hr)) {
            *ppvObj = new FakeTexture(orig_tex);
        }
        return hr;
    }
    gog_debug("Unused function called: FakeSurface4::QueryInterface");
    return DDERR_GENERIC;
}

ULONG FakeSurface4::Release(void) {
    if (--this->refs != 0)
        return this->refs;
    if (this->f8_orig_surf) {
        this->f8_orig_surf->Release();
        this->f8_orig_surf = nullptr;
    }
    operator delete(this);
    return 0;
}

HRESULT FakeSurface4::AddAttachedSurface(LPDIRECTDRAWSURFACE4) {
    gog_debug("Unused function called: FakeSurface4::AddAttachedSurface");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::AddOverlayDirtyRect(LPRECT) {
    gog_debug("Unused function called: FakeSurface4::AddOverlayDirtyRect");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::Blt(LPRECT, LPDIRECTDRAWSURFACE4, LPRECT, DWORD, LPDDBLTFX) {
    gog_debug("Unused function called: FakeSurface4::Blt");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::BltBatch(LPDDBLTBATCH, DWORD, DWORD) {
    gog_debug("Unused function called: FakeSurface4::BltBatch");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::BltFast(DWORD x, DWORD y, LPDIRECTDRAWSURFACE4 srcSurf_, LPRECT srcRect, DWORD a6) {
    auto *srcSurf = (FakeSurface4 *) srcSurf_;
    if (!srcSurf) gog_debug("Assertion failed: FakeSurface4::BltFast:264");
    if (this->fC_isModSurf) gog_debug("Assertion failed: FakeSurface4::BltFast:265");
    IDirectDrawSurface4 *srcSurf_1 = nullptr;
    if (srcSurf) srcSurf_1 = srcSurf->f8_orig_surf;
    HRESULT hr;
    hr = this->f8_orig_surf->BltFast(x, y, srcSurf_1, srcRect, a6);
    if (FAILED(hr)) {
        gog_debugf("Assertion failed: FakeSurface4::BltFast:282 with HRESULT 0x%x", hr);
        return hr;
    }
    if (!this->fC_isModSurf) return hr;
    if (!orig::pIDirectDrawSurface4_coop) {
        gog_debug("Assertion failed: FakeSurface4::BltFast:285");
    }
    orig::pIDirectDrawSurface4_coop->Blt(&g_renderRect, this->f8_orig_surf, NULL, 0x1000000, NULL);
    return hr;
}

HRESULT FakeSurface4::DeleteAttachedSurface(DWORD, LPDIRECTDRAWSURFACE4) {
    gog_debug("Unused function called: FakeSurface4::DeleteAttachedSurface");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::EnumAttachedSurfaces(LPVOID, LPDDENUMSURFACESCALLBACK2) {
    gog_debug("Unused function called: FakeSurface4::EnumAttachedSurfaces");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::EnumOverlayZOrders(DWORD, LPVOID, LPDDENUMSURFACESCALLBACK2) {
    gog_debug("Unused function called: FakeSurface4::EnumOverlayZOrders");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::Flip(LPDIRECTDRAWSURFACE4, DWORD) {
    gog_debug("Unused function called: FakeSurface4::Flip");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetAttachedSurface(LPDDSCAPS2, LPDIRECTDRAWSURFACE4 *) {
    gog_debug("Unused function called: FakeSurface4::GetAttachedSurface");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetBltStatus(DWORD) {
    gog_debug("Unused function called: FakeSurface4::GetBltStatus");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetCaps(LPDDSCAPS2) {
    gog_debug("Unused function called: FakeSurface4::GetCaps");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetClipper(LPDIRECTDRAWCLIPPER *) {
    gog_debug("Unused function called: FakeSurface4::GetClipper");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetColorKey(DWORD, LPDDCOLORKEY) {
    gog_debug("Unused function called: FakeSurface4::GetColorKey");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetDC(HDC *) {
    gog_debug("Unused function called: FakeSurface4::GetDC");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetFlipStatus(DWORD) {
    gog_debug("Unused function called: FakeSurface4::GetFlipStatus");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetOverlayPosition(LPLONG, LPLONG) {
    gog_debug("Unused function called: FakeSurface4::GetOverlayPosition");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetPalette(LPDIRECTDRAWPALETTE *) {
    gog_debug("Unused function called: FakeSurface4::GetPalette");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetPixelFormat(LPDDPIXELFORMAT) {
    gog_debug("Unused function called: FakeSurface4::GetPixelFormat");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetSurfaceDesc(LPDDSURFACEDESC2) {
    gog_debug("Unused function called: FakeSurface4::GetSurfaceDesc");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::Initialize(LPDIRECTDRAW, LPDDSURFACEDESC2) {
    gog_debug("Unused function called: FakeSurface4::Initialize");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::IsLost(void) {
    return DD_OK;
}

HRESULT FakeSurface4::Lock(LPRECT pRect, LPDDSURFACEDESC2 surf, DWORD a4, HANDLE a5) {
    HRESULT hr = this->f8_orig_surf->Lock(pRect, surf, a4, a5);
    if (FAILED(hr)) {
        gog_debugf("Assertion failed: FakeSurface4::Lock:309 with HRESULT 0x%x", hr);
        return hr;
    }
    ++this->f10_lockCounter;
    return hr;
}

HRESULT FakeSurface4::ReleaseDC(HDC) {
    gog_debug("Unused function called: FakeSurface4::ReleaseDC");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::Restore(void) {
    return DD_OK;
}

HRESULT FakeSurface4::SetClipper(LPDIRECTDRAWCLIPPER) {
    gog_debug("Unused function called: FakeSurface4::SetClipper");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::SetColorKey(DWORD, LPDDCOLORKEY) {
    gog_debug("Unused function called: FakeSurface4::SetColorKey");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::SetOverlayPosition(LONG, LONG) {
    gog_debug("Unused function called: FakeSurface4::SetOverlayPosition");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::SetPalette(LPDIRECTDRAWPALETTE) {
    gog_debug("Unused function called: FakeSurface4::SetPalette");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::Unlock(LPRECT pRect) {
    HRESULT hr = this->f8_orig_surf->Unlock(pRect);
    if (FAILED(hr)) {
        gog_debugf("Assertion failed: FakeSurface4::Unlock:322 with HRESULT 0x%x", hr);
        return hr;
    }
    --this->f10_lockCounter;
    if (this->fC_isModSurf) {
        if (!this->f10_lockCounter) Fake_Redraw();
    }
    return hr;
}

HRESULT FakeSurface4::UpdateOverlay(LPRECT, LPDIRECTDRAWSURFACE4, LPRECT, DWORD, LPDDOVERLAYFX) {
    gog_debug("Unused function called: FakeSurface4::UpdateOverlay");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::UpdateOverlayDisplay(DWORD) {
    gog_debug("Unused function called: FakeSurface4::UpdateOverlayDisplay");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::UpdateOverlayZOrder(DWORD, LPDIRECTDRAWSURFACE4) {
    gog_debug("Unused function called: FakeSurface4::UpdateOverlayZOrder");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetDDInterface(LPVOID *) {
    gog_debug("Unused function called: FakeSurface4::GetDDInterface");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::PageLock(DWORD) {
    gog_debug("Unused function called: FakeSurface4::PageLock");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::PageUnlock(DWORD) {
    gog_debug("Unused function called: FakeSurface4::PageUnlock");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::SetSurfaceDesc(LPDDSURFACEDESC2, DWORD) {
    gog_debug("Unused function called: FakeSurface4::SetSurfaceDesc");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::SetPrivateData(REFGUID, LPVOID, DWORD, DWORD) {
    gog_debug("Unused function called: FakeSurface4::SetPrivateData");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetPrivateData(REFGUID, LPVOID, LPDWORD) {
    gog_debug("Unused function called: FakeSurface4::GetPrivateData");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::FreePrivateData(REFGUID) {
    gog_debug("Unused function called: FakeSurface4::FreePrivateData");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::GetUniquenessValue(LPDWORD) {
    gog_debug("Unused function called: FakeSurface4::GetUniquenessValue");
    return DDERR_GENERIC;
}

HRESULT FakeSurface4::ChangeUniquenessValue(void) {
    gog_debug("Unused function called: FakeSurface4::ChangeUniquenessValue");
    return DDERR_GENERIC;
}
