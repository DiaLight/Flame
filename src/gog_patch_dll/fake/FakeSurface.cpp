//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeSurface.h>
#include <gog_globals.h>
#include <gog_cfg.h>
#include <gog_fake.h>
#include <fake/FakeSurface4.h>
#include <gog_debug.h>

using namespace gog;

FakeSurface *FakeSurface::instance_mod = nullptr;
FakeSurface *FakeSurface::instance_cpy = nullptr;

FakeSurface::FakeSurface(IDirectDrawSurface4 *orig_surf) {
    this->f84_isModSurf = false;
    this->f8C_lockedRect.left = 0;
    this->f8C_lockedRect.top = 0;
    this->f8C_lockedRect.right = 0;
    this->f8C_lockedRect.bottom = 0;
    this->f9C_pLockedRect = nullptr;
    this->f88_orig_surf = orig_surf;
    memset(&this->f8_surfDesc, 0, sizeof(this->f8_surfDesc));
    this->f8_surfDesc.dwSize = 124;
    HRESULT hr = this->f88_orig_surf->GetSurfaceDesc(&this->f8_surfDesc);
    if (FAILED(hr)) {
        gog_assert_failed_hr("FakeSurface::FakeSurface:364", hr);
    }
    this->f88_orig_surf->AddRef();
}

FakeSurface::FakeSurface(DDSURFACEDESC2 *desc) {
    this->f8C_lockedRect.left = 0;
    this->f8C_lockedRect.top = 0;
    this->f8C_lockedRect.right = 0;
    this->f8C_lockedRect.bottom = 0;
    this->f9C_pLockedRect = 0;
    DDSURFACEDESC2 descCpy;
    memset(&descCpy, 0, sizeof(descCpy));
    memcpy(&descCpy, desc, desc->dwSize);
    DWORD dwFlags = descCpy.dwFlags;
    descCpy.dwSize = 124;
    if (
            (descCpy.dwFlags & 1) != 0 &&
            (descCpy.ddsCaps.dwCaps & 0x200) != 0 &&
            (descCpy.dwFlags & 4) == 0
            ) {
        if (FakeSurface::instance_mod) {
            gog_assert_failed("FakeSurface::FakeSurface:377");
            dwFlags = descCpy.dwFlags;
        }
        static_assert(8 == DDSCAPS_COMPLEX);
        static_assert(0x10 == DDSCAPS_FLIP);
        if ((descCpy.ddsCaps.dwCaps & DDSCAPS_COMPLEX) == 0 || (descCpy.ddsCaps.dwCaps & DDSCAPS_FLIP) == 0) {
            gog_assert_failed("FakeSurface::FakeSurface:379");
            dwFlags = descCpy.dwFlags;
        }
        DWORD v4 = gog::g_dwWidth;
        descCpy.ddsCaps.dwCaps &= 0xFFFFDDE7;
        this->f84_isModSurf = true;
        if (v4 == 640 && g_isAntialiasGt10)
            descCpy.ddsCaps.dwCaps |= 0x840u;
        dwFlags = dwFlags ^ 0x20 | 0x1006;
        descCpy.dwFlags = dwFlags;
        descCpy.dwHeight = g_dwHeight;
        descCpy.dwBackBufferCount = 0;
        descCpy.dwWidth = v4;
        descCpy.ddpfPixelFormat.dwSize = sizeof(DDPIXELFORMAT);
        static_assert(sizeof(DDPIXELFORMAT) == 0x20);
        descCpy.ddpfPixelFormat.dwFlags = DDPF_RGB;
        descCpy.ddpfPixelFormat.dwRGBBitCount = 32;
        descCpy.ddpfPixelFormat.dwRBitMask = 0xFF0000;
        descCpy.ddpfPixelFormat.dwGBitMask = 0xFF00;
        descCpy.ddpfPixelFormat.dwBBitMask = 0xFF;
        descCpy.ddpfPixelFormat.dwRGBAlphaBitMask = 0;
        descCpy.ddpfPixelFormat.dwFourCC = 0;
        FakeSurface::instance_mod = this;
    } else {
        this->f84_isModSurf = false;
        if ((dwFlags & 0x1000) != 0 && descCpy.ddpfPixelFormat.dwFlags != 4) {
            gog_assert_failed("FakeSurface::FakeSurface:413");
            dwFlags = descCpy.dwFlags;
        }
    }
    if ((dwFlags & 0x1000) == 0) {
        dwFlags |= 0x1000u;
        descCpy.dwFlags = dwFlags;
        descCpy.ddpfPixelFormat.dwSize = sizeof(DDPIXELFORMAT);
        static_assert(sizeof(DDPIXELFORMAT) == 0x20);
        descCpy.ddpfPixelFormat.dwFlags = DDPF_RGB;
        descCpy.ddpfPixelFormat.dwRGBBitCount = 32;
        descCpy.ddpfPixelFormat.dwRBitMask = 0xFF0000;
        descCpy.ddpfPixelFormat.dwGBitMask = 0xFF00;
        descCpy.ddpfPixelFormat.dwBBitMask = 0xFF;
        descCpy.ddpfPixelFormat.dwRGBAlphaBitMask = 0;
    }
    if ((dwFlags & 0x40) != 0 || (descCpy.ddsCaps.dwCaps & 0x20000) != 0) gog_assert_failed("FakeSurface::FakeSurface:437");
    memcpy(&this->f8_surfDesc, &descCpy, sizeof(this->f8_surfDesc));
    if (!this->f8_surfDesc.dwWidth) gog_assert_failed("FakeSurface::FakeSurface:441");
    if (!this->f8_surfDesc.dwHeight) gog_assert_failed("FakeSurface::FakeSurface:442");

    static_assert(0x88760064 == DDERR_INVALIDCAPS);
    LPDIRECTDRAWSURFACE4 *p_f88_orig_surf = &this->f88_orig_surf;
    this->f88_orig_surf = nullptr;
    HRESULT v6 = orig::pIDirectDraw4->CreateSurface(&this->f8_surfDesc, &this->f88_orig_surf, NULL);
    if (FAILED(v6)) {
        gog_assert_failed_hr("FakeSurface::FakeSurface:446", v6);
        gog_debugf("Width = %d\nHeight = %d\nCaps = 0x%x\npfType = 0x%x",
                   this->f8_surfDesc.dwWidth,
                   this->f8_surfDesc.dwHeight,
                   this->f8_surfDesc.ddsCaps.dwCaps,
                   this->f8_surfDesc.ddpfPixelFormat.dwFlags);
        *p_f88_orig_surf = nullptr;
        return;
    }
    if (!this->f84_isModSurf) return;
    if (FakeSurface::instance_cpy) {
        gog_assert_failed("FakeSurface::FakeSurface:456");
    }
    orig::pIDirectDrawSurface4_last = *p_f88_orig_surf;

    DDSURFACEDESC2 surfDesc;
    memcpy(&surfDesc, &this->f8_surfDesc, sizeof(surfDesc));
    if (!cfg::iAntialias || g_dwWidth > 0x400u)
        surfDesc.ddsCaps.dwCaps |= 0x2000u;
    IDirectDrawSurface4 *orig_surf;
    HRESULT v8 = orig::pIDirectDraw4->CreateSurface(&surfDesc, &orig_surf, NULL);
    if (FAILED(v8)) {
        gog_assert_failed_hr("FakeSurface::FakeSurface:467", v8);
        gog_debugf("Width = %d\nHeight = %d\nCaps = 0x%x\npfType = 0x%x",
                   surfDesc.dwWidth,
                   surfDesc.dwHeight,
                   surfDesc.ddsCaps.dwCaps,
                   surfDesc.ddpfPixelFormat.dwFlags);
        this->f88_orig_surf = nullptr;
        return;
    }

    FakeSurface::instance_cpy = new FakeSurface(orig_surf);
    if (cfg::iAntialias && g_dwWidth <= 1024) {
        DDSURFACEDESC2 desc3;
        memcpy(&desc3, &descCpy, sizeof(desc3));
        desc3.ddsCaps.dwCaps = 24640;
        desc3.ddsCaps.dwCaps2 = 0;
        if (cfg::iExtraAntialias) {
            desc3.ddsCaps.dwCaps2 = 256;
        }
        desc3.dwHeight *= cfg::iAntialias;
        desc3.dwWidth *= cfg::iAntialias;
        HRESULT v11 = orig::pIDirectDraw4->CreateSurface(
                &desc3,
                &orig::pIDirectDrawSurface4_zbuf,
                NULL
        );
        if (FAILED(v11)) {
            gog_assert_failed_hr("FakeSurface::FakeSurface:489", v11);
            gog_debugf("Width = %d\nHeight = %d\nCaps = 0x%x\npfType = 0x%x",
                       desc3.dwWidth,
                       desc3.dwHeight,
                       desc3.ddsCaps.dwCaps,
                       desc3.ddpfPixelFormat.dwFlags);
            this->f88_orig_surf = nullptr;
            return;
        }
        IDirectDrawSurface4 *ZBuf = (IDirectDrawSurface4 *) Fake_CreateZBuf(g_dwWidth * cfg::iAntialias,
                                                                            g_dwHeight * cfg::iAntialias);
        HRESULT v13 = orig::pIDirectDrawSurface4_zbuf->AddAttachedSurface(ZBuf);
        if (FAILED(v13)) {
            gog_assert_failed_hr("FakeSurface::FakeSurface:500", v13);
        }
        ZBuf->Release();
    } else {
        IDirectDrawSurface4 *ZBuf = (IDirectDrawSurface4 *) Fake_CreateZBuf(g_dwWidth, g_dwHeight);
        HRESULT v14 = orig_surf->AddAttachedSurface(ZBuf);
        if (FAILED(v14)) {
            gog_assert_failed_hr("FakeSurface::FakeSurface:504", v14);
        }
        ZBuf->Release();
    }
}

HRESULT FakeSurface::QueryInterface(REFIID riid, LPVOID FAR *ppvObj) {
    if (IsEqualGUID(IID_IDirectDrawSurface2, riid)) {
        *ppvObj = this;
        this->AddRef();
        return DD_OK;
    } else if (IsEqualGUID(IID_IDirectDrawSurface4, riid)) {
        *ppvObj = new FakeSurface4(this->f88_orig_surf, this->f84_isModSurf);
        return DD_OK;
    } else {
        gog_unused_function_called("FakeSurface::QueryInterface");
        return DDERR_GENERIC;
    }
}

ULONG FakeSurface::Release(void) {
    ULONG v1 = this->refs-- == 1;
    ULONG result = this->refs;
    if (v1 == 0) return result;
    if (this->f84_isModSurf) {
        if (FakeSurface::instance_cpy) {
            FakeSurface::instance_cpy->Release();
            FakeSurface::instance_cpy = nullptr;
        }
        if (orig::pIDirectDrawSurface4_zbuf) {
            orig::pIDirectDrawSurface4_zbuf->Release();
            orig::pIDirectDrawSurface4_zbuf = nullptr;
        }
        FakeSurface::instance_mod = nullptr;
    }
    LPDIRECTDRAWSURFACE4 f88_orig_surf = this->f88_orig_surf;
    if (f88_orig_surf) {
        f88_orig_surf->Release();
        this->f88_orig_surf = nullptr;
    }
    operator delete(this);
    return 0;
}

HRESULT FakeSurface::AddAttachedSurface(LPDIRECTDRAWSURFACE2 a2) {
    if (!a2) gog_assert_failed("FakeSurface::AddAttachedSurface:539");
    if (this != FakeSurface::instance_cpy) gog_assert_failed("FakeSurface::AddAttachedSurface:540");
    return 0;
}

HRESULT FakeSurface::AddOverlayDirtyRect(LPRECT) {
    gog_unused_function_called("FakeSurface::AddOverlayDirtyRect");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::Blt(LPRECT dstRect, LPDIRECTDRAWSURFACE2 srcSurf_, LPRECT srcRect, DWORD flags, LPDDBLTFX bitblt) {
    auto *srcSurf = (FakeSurface *) srcSurf_;
    HRESULT hr;
    if (!orig::pIDirectDrawSurface4_640x480 || !this->f84_isModSurf || !srcSurf) {
        IDirectDrawSurface4 *src = nullptr;
        if (srcSurf) src = srcSurf->f88_orig_surf;
        hr = this->f88_orig_surf->Blt(dstRect, src, srcRect, flags, bitblt);
        if (FAILED(hr)) return hr;
        if (this->f84_isModSurf) Fake_Redraw();
        return hr;
    }
    if (srcSurf->f8_surfDesc.ddpfPixelFormat.dwFlags != 4) {
        hr = (HRESULT) srcSurf;
        if (FAILED(hr)) return hr;
        if (this->f84_isModSurf) Fake_Redraw();
        return hr;
    }
    hr = orig::pIDirectDrawSurface4_640x480->Blt(dstRect, srcSurf->f88_orig_surf, srcRect, flags, bitblt);
    if (FAILED(hr)) {
        gog_assert_failed_hr("FakeSurface::Blt:564", hr);
        return hr;
    }
    hr = this->f88_orig_surf->Blt(NULL, orig::pIDirectDrawSurface4_640x480, NULL, 0x1000000, NULL);
    if (FAILED(hr)) {
        gog_assert_failed_hr("FakeSurface::Blt:567", hr);
        return hr;
    }
    if (this->f84_isModSurf) Fake_Redraw();
    return hr;
}

HRESULT FakeSurface::BltBatch(LPDDBLTBATCH, DWORD, DWORD) {
    gog_unused_function_called("FakeSurface::BltBatch");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::BltFast(DWORD x, DWORD y, LPDIRECTDRAWSURFACE2 srcSurf_, LPRECT srcRect, DWORD type) {
    auto *srcSurf = (FakeSurface *) srcSurf_;
    IDirectDrawSurface4 *f88_orig_surf;
    int hr;
    if (gog::g_isSmth_noRef && (this == FakeSurface::instance_mod || this == FakeSurface::instance_cpy))
        return 0;
    if (srcSurf) {
        f88_orig_surf = srcSurf->f88_orig_surf;
    } else {
        gog_assert_failed("FakeSurface::BltFast:580");
        f88_orig_surf = nullptr;
    }
    hr = this->f88_orig_surf->BltFast(x, y, f88_orig_surf, srcRect, type);
    if (FAILED(hr)) return hr;
    if (this->f84_isModSurf) Fake_Redraw();
    return hr;
}

HRESULT FakeSurface::DeleteAttachedSurface(DWORD, LPDIRECTDRAWSURFACE2) {
    gog_unused_function_called("FakeSurface::DeleteAttachedSurface");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::EnumAttachedSurfaces(LPVOID, LPDDENUMSURFACESCALLBACK) {
    gog_unused_function_called("FakeSurface::EnumAttachedSurfaces");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::EnumOverlayZOrders(DWORD, LPVOID, LPDDENUMSURFACESCALLBACK) {
    gog_unused_function_called("FakeSurface::EnumOverlayZOrders");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::Flip(LPDIRECTDRAWSURFACE2 a2, DWORD flags) {
    if (!this->f84_isModSurf) gog_assert_failed("FakeSurface::Flip:606");
    if (!orig::pIDirectDrawSurface4_coop) gog_assert_failed("FakeSurface::Flip:607");
    if (a2 && a2 != FakeSurface::instance_cpy) gog_assert_failed("FakeSurface::Flip:608");
    if (gog::g_isSceneDrawing) gog_assert_failed("FakeSurface::Flip:609");
    if (cfg::iCpuIdle)
        Sleep(cfg::iCpuIdle);
    this->f88_orig_surf->Blt(NULL, FakeSurface::instance_cpy->f88_orig_surf, NULL, 0x1000000, NULL);
    if (cfg::iVwait) {
        if (cfg::iVwait == 1)
            orig::pIDirectDraw4->WaitForVerticalBlank(1, NULL);
        else
            orig::pIDirectDraw4->WaitForVerticalBlank(4, NULL);
    }
    Fake_Redraw();
    gog::g_isFlip = true;
    return DD_OK;
}

HRESULT FakeSurface::GetAttachedSurface(LPDDSCAPS a2, LPDIRECTDRAWSURFACE2 *a3) {
    if (!this->f84_isModSurf) gog_assert_failed("FakeSurface::GetAttachedSurface:635");
    if ((a2->dwCaps & 4) == 0) gog_assert_failed("FakeSurface::GetAttachedSurface:636");
    *a3 = FakeSurface::instance_cpy;
    FakeSurface::instance_cpy->AddRef();
    return DD_OK;
}

HRESULT FakeSurface::GetBltStatus(DWORD) {
    gog_unused_function_called("FakeSurface::GetBltStatus");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::GetCaps(LPDDSCAPS) {
    gog_unused_function_called("FakeSurface::GetCaps");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::GetClipper(LPDIRECTDRAWCLIPPER *) {
    gog_unused_function_called("FakeSurface::GetClipper");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::GetColorKey(DWORD, LPDDCOLORKEY) {
    gog_unused_function_called("FakeSurface::GetColorKey");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::GetDC(HDC *) {
    gog_unused_function_called("FakeSurface::GetDC");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::GetFlipStatus(DWORD) {
    gog_unused_function_called("FakeSurface::GetFlipStatus");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::GetOverlayPosition(LPLONG, LPLONG) {
    gog_unused_function_called("FakeSurface::GetOverlayPosition");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::GetPalette(LPDIRECTDRAWPALETTE *) {
    gog_unused_function_called("FakeSurface::GetPalette");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::GetPixelFormat(LPDDPIXELFORMAT a2) {
    memcpy(a2, &this->f8_surfDesc.ddpfPixelFormat, sizeof(DDPIXELFORMAT));
    return DD_OK;
}

HRESULT FakeSurface::GetSurfaceDesc(LPDDSURFACEDESC pDesc) {
    DDSURFACEDESC2 desc;
    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(DDSURFACEDESC2);
    static_assert(sizeof(DDSURFACEDESC2) == 124);
    HRESULT hr = this->f88_orig_surf->GetSurfaceDesc(&desc);
    if (FAILED(hr)) return hr;
    DWORD dwSize = pDesc->dwSize;
    memcpy(pDesc, &desc, pDesc->dwSize);
    pDesc->dwSize = dwSize;
    return hr;
}

HRESULT FakeSurface::Initialize(LPDIRECTDRAW, LPDDSURFACEDESC) {
    gog_unused_function_called("FakeSurface::Initialize");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::IsLost(void) {
    return DD_OK;
}

HRESULT FakeSurface::Lock(LPRECT pRect, LPDDSURFACEDESC pDesc, DWORD a4, HANDLE a5) {
    if (g_isSmth_noRef && (this == FakeSurface::instance_mod || this == FakeSurface::instance_cpy))
        return DDERR_GENERIC;
    if (this->f9C_pLockedRect) gog_assert_failed("FakeSurface::Lock:672");
    DDSURFACEDESC2 desc;
    memset(&desc, 0, sizeof(desc));
    desc.dwSize = sizeof(DDSURFACEDESC2);
    static_assert(sizeof(DDSURFACEDESC2) == 124);

    HRESULT hr = this->f88_orig_surf->Lock(pRect, &desc, a4, a5);
    if (FAILED(hr)) return hr;

    DWORD dwSize = pDesc->dwSize;
    memcpy(pDesc, &desc, pDesc->dwSize);
    pDesc->dwSize = dwSize;

    if (!pRect) return hr;
    this->f8C_lockedRect = *pRect;
    this->f9C_pLockedRect = &this->f8C_lockedRect;
    return hr;
}

HRESULT FakeSurface::ReleaseDC(HDC) {
    gog_unused_function_called("FakeSurface::ReleaseDC");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::Restore(void) {
    return DD_OK;
}

HRESULT FakeSurface::SetClipper(LPDIRECTDRAWCLIPPER) {
    return DD_OK;
}

HRESULT FakeSurface::SetColorKey(DWORD a2, LPDDCOLORKEY a3) {
    return this->f88_orig_surf->SetColorKey(a2, a3);
}

HRESULT FakeSurface::SetOverlayPosition(LONG, LONG) {
    gog_unused_function_called("FakeSurface::SetOverlayPosition");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::SetPalette(LPDIRECTDRAWPALETTE) {
    gog_unused_function_called("FakeSurface::SetPalette");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::Unlock(LPVOID) {
    HRESULT hr = this->f88_orig_surf->Unlock(this->f9C_pLockedRect);
    if (FAILED(hr)) return hr;
    if (this->f84_isModSurf) Fake_Redraw();
    return hr;
}

HRESULT FakeSurface::UpdateOverlay(LPRECT, LPDIRECTDRAWSURFACE2, LPRECT, DWORD, LPDDOVERLAYFX) {
    gog_unused_function_called("FakeSurface::UpdateOverlay");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::UpdateOverlayDisplay(DWORD) {
    gog_unused_function_called("FakeSurface::UpdateOverlayDisplay");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::UpdateOverlayZOrder(DWORD, LPDIRECTDRAWSURFACE2) {
    gog_unused_function_called("FakeSurface::UpdateOverlayZOrder");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::GetDDInterface(LPVOID *) {
    gog_unused_function_called("FakeSurface::GetDDInterface");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::PageLock(DWORD) {
    gog_unused_function_called("FakeSurface::PageLock");
    return DDERR_GENERIC;
}

HRESULT FakeSurface::PageUnlock(DWORD) {
    gog_unused_function_called("FakeSurface::PageUnlock");
    return DDERR_GENERIC;
}

