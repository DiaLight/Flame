//
// Created by DiaLight on 20.01.2023.
//
#include <gog_fake.h>
#include <fake/FakeGammaControl.h>
#include <fake/FakeViewport3.h>
#include <fake/FakeD3D.h>
#include <fake/FakeD3D2.h>
#include <fake/FakeZBuffer.h>
#include <cstdint>
#include <gog_globals.h>
#include <gog_cfg.h>
#include <cmath>
#include <gog_debug.h>


void gog::fakeInit() {
    FakeGammaControl::instance = new FakeGammaControl();
    FakeViewport3::instance = new FakeViewport3();
    FakeD3D::instance = new FakeD3D();
    FakeD3D2::instance = new FakeD3D2();
    FakeZBuffer::instance = new FakeZBuffer();
}

LPDIRECTDRAWSURFACE4 gog::Fake_CreateZBuf(DWORD width, DWORD height) {
    DDSURFACEDESC2 desc;
    memset(&desc, 0, sizeof(desc));
    desc.dwSize = 124;
    desc.dwFlags = 0x1007;
    desc.ddsCaps.dwCaps = 0x24000;
    desc.ddpfPixelFormat.dwSize = 32;
    desc.ddpfPixelFormat.dwFlags = 0x400;
    desc.ddpfPixelFormat.dwRGBBitCount = 32;
    desc.ddpfPixelFormat.dwGBitMask = 0xFFFFFF;
    desc.dwWidth = width;
    desc.dwHeight = height;
    gog_debug("Creating Z-Buffer.");
    LPDIRECTDRAWSURFACE4 surf;
    HRESULT hr;
    hr = orig::pIDirectDraw4->CreateSurface(&desc, &surf, NULL);
    if (SUCCEEDED(hr))
        return surf;
    gog_debug("ZBuf creation failed. Retrying with alternate bit order.");
    desc.ddpfPixelFormat.dwGBitMask = 0xFFFFFF00;
    hr = orig::pIDirectDraw4->CreateSurface(&desc, &surf, NULL);
    if (SUCCEEDED(hr))
        return surf;
    gog_debug("ZBuf creation failed. Retrying with lower bit depth.");
    desc.ddpfPixelFormat.dwRGBBitCount = 16;
    desc.ddpfPixelFormat.dwGBitMask = 0xFFFF;
    hr = orig::pIDirectDraw4->CreateSurface(&desc, &surf, NULL);
    if (SUCCEEDED(hr))
        return surf;
    gog_debugf("Assertion failed: CreateZBuf:146 with HRESULT 0x%x", hr);
    gog_debugf("Width = %d\nHeight = %d\nCaps = 0x%x\npfType = 0x%x",
               desc.dwWidth,
               desc.dwHeight,
               desc.ddsCaps.dwCaps,
               desc.ddpfPixelFormat.dwFlags);
    return surf;
}

void gog::Fake_Redraw() {
    if (orig::pIDirectDrawSurface4_coop == nullptr) {
        gog_debug("Assertion failed: Redraw:51");
    }
    if (g_isRendererPaused) return;
    HRESULT hr = orig::pIDirectDrawSurface4_coop->Blt(
            &gog::g_renderRect,
            orig::pIDirectDrawSurface4_last, NULL, 0x1000000, NULL);
    if (hr != DDERR_SURFACELOST) return;
    static_assert(DDERR_SURFACELOST == 0x887601C2);
    gog_debug("Restoring all surfaces");
    orig::pIDirectDraw4->RestoreAllSurfaces();
    if (gog::g_isColorFill)
        orig::pIDirectDrawSurface4_coop->Blt(NULL, NULL, NULL, DDBLT_COLORFILL | DDBLT_WAIT, NULL);
    static_assert((DDBLT_COLORFILL | DDBLT_WAIT) == 0x1000400);
}

void gog::Fake_InitRenderRect() {
    RECT rect;
    GetClientRect(g_hWnd, &rect);
    unsigned int width = rect.right - rect.left;
    unsigned int height = rect.bottom - rect.top;
    if (!cfg::iScaleMode) {
        gog::g_renderRect = rect;
        return;
    }
    if (cfg::iScaleMode == 2) {
        if (width > gog::g_dwWidth && height > gog::g_dwHeight) {
            gog::g_renderRect.left = rect.left + ((width - gog::g_dwWidth) >> 1);
            gog::g_renderRect.top = rect.top + ((height - gog::g_dwHeight) >> 1);
            gog::g_renderRect.right = gog::g_dwWidth + gog::g_renderRect.left;
            gog::g_renderRect.bottom = gog::g_dwHeight + gog::g_renderRect.top;
            gog::g_isColorFill = true;
            return;
        }
    } else if (cfg::iScaleMode == 3 && width > gog::g_dwWidth && height > gog::g_dwHeight) {
        gog::g_renderRect.top = rect.top;
        gog::g_renderRect.bottom = rect.top + gog::g_dwHeight;
        gog::g_renderRect.right = rect.left + gog::g_dwWidth;
        gog::g_renderRect.left = rect.left;
        gog::g_isColorFill = true;
        return;
    }
    double dWidth = (double) (unsigned int) gog::g_dwWidth;
    double dHeight = (double) (unsigned int) gog::g_dwHeight;
    double dWigth2 = (double) width;
    double dHeight2 = (double) height;
    if (fabs((dWigth2 / dHeight2) - (dWidth / dHeight)) >= 0.00001) {
        gog::g_isColorFill = true;
        if ((dWigth2 / dHeight2) <= (dWidth / dHeight)) {
            int scaledHeight = (int) (dWigth2 / dWidth * dHeight);
            gog::g_renderRect.left = rect.left;
            gog::g_renderRect.top = rect.top + ((height - scaledHeight) >> 1);
            gog::g_renderRect.bottom = scaledHeight + gog::g_renderRect.top;
            gog::g_renderRect.right = rect.right;
        } else {
            int scaledWidth = (int) (dWidth * (dHeight2 / dHeight));
            gog::g_renderRect.left = rect.left + ((width - scaledWidth) >> 1);
            gog::g_renderRect.top = rect.top;
            gog::g_renderRect.bottom = rect.bottom;
            gog::g_renderRect.right = scaledWidth + gog::g_renderRect.left;
        }
    } else {
        gog::g_renderRect = rect;
    }
}

