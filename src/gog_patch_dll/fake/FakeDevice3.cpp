//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeDevice3.h>
#include <gog_globals.h>
#include <gog_cfg.h>
#include <fake/FakeSurface.h>
#include <fake/FakeTexture.h>
#include <gog_debug.h>
#include <dk2/TexCoord.h>
#include <dk2/Vertex1C.h>

using namespace gog;

FakeDevice3::FakeDevice3() {
    orig::pIDirect3D3->CreateViewport(&orig::pIDirect3DViewport3, NULL);
    DWORD height = g_dwHeight;
    DWORD width = g_dwWidth;
    D3DVIEWPORT2 viewport;
    viewport.dwSize = sizeof(D3DVIEWPORT2);
    static_assert(sizeof(D3DVIEWPORT2) == 44);
    viewport.dwX = 0;
    viewport.dwY = 0;
    viewport.dwWidth = g_dwWidth;
    viewport.dwHeight = g_dwHeight;
    if (cfg::iAntialias && orig::pIDirectDrawSurface4_zbuf) {
        width = g_dwWidth * cfg::iAntialias;
        height = g_dwHeight * cfg::iAntialias;
        viewport.dwWidth = g_dwWidth * cfg::iAntialias;
        viewport.dwHeight = g_dwHeight * cfg::iAntialias;
    }
    viewport.dvClipX = -1.0;
    viewport.dvClipY = -((double) (unsigned int) height / (double) (unsigned int) width);
    viewport.dvClipWidth = 2.0;
    viewport.dvClipHeight = -viewport.dvClipY - viewport.dvClipY;
    viewport.dvMinZ = 0.0;
    viewport.dvMaxZ = 1.0;
    HRESULT hr = orig::pIDirect3DDevice3->AddViewport(orig::pIDirect3DViewport3);
    if (FAILED(hr)) {
        gog_debugf("Assertion failed: FakeDevice3::FakeDevice3:742 with HRESULT 0x%x", hr);
    }
    hr = orig::pIDirect3DViewport3->SetViewport2(&viewport);
    if (FAILED(hr)) {
        gog_debugf("Assertion failed: FakeDevice3::FakeDevice3:744 with HRESULT 0x%x", hr);
    }
    hr = orig::pIDirect3DDevice3->SetCurrentViewport(orig::pIDirect3DViewport3);
    if (FAILED(hr)) {
        gog_debugf("Assertion failed: FakeDevice3::FakeDevice3:746 with HRESULT 0x%x", hr);
    }
    if (cfg::iExtraAntialias) {
        hr = orig::pIDirect3DDevice3->SetRenderState((D3DRENDERSTATETYPE) 2, 2);
        if (FAILED(hr)) {
            gog_debugf("Assertion failed: FakeDevice3::FakeDevice3:750 with HRESULT 0x%x", hr);
        }
    }
    if (!cfg::iAnisotropy) {
        hr = orig::pIDirect3DDevice3->SetTextureStageState(0, D3DTSS_MAXANISOTROPY, 16);
        if (FAILED(hr)) {
            gog_debugf("Assertion failed: FakeDevice3::FakeDevice3:755 with HRESULT 0x%x", hr);
        }
    }
}

HRESULT FakeDevice3::QueryInterface(REFIID riid, LPVOID *ppvObj) {
    gog_debug("Unused function called: FakeDevice3::QueryInterface");
    return DDERR_GENERIC;
}

ULONG FakeDevice3::Release(void) {
    if (--refs != 0) return refs;
    if (orig::pIDirect3DViewport3) {
        orig::pIDirect3DViewport3->Release();
        orig::pIDirect3DViewport3 = nullptr;
    }
    if (orig::pIDirect3DDevice3) {
        orig::pIDirect3DDevice3->Release();
        orig::pIDirect3DDevice3 = nullptr;
    }
    operator delete(this);
    return 0;
}

HRESULT FakeDevice3::GetCaps(LPD3DDEVICEDESC hwDesc, LPD3DDEVICEDESC halDesc) {
    D3DDEVICEDESC hwDesc_;
    hwDesc_.dwSize = sizeof(D3DDEVICEDESC);
    static_assert(sizeof(D3DDEVICEDESC) == 252);
    hwDesc_.dwFlags = 0x1FF;
    hwDesc_.dcmColorModel = 2;
    hwDesc_.dwDevCaps = 0x61BBEF1;
    hwDesc_.dtcTransformCaps.dwSize = 8;
    hwDesc_.dtcTransformCaps.dwCaps = 1;
    hwDesc_.bClipping = 1;
    hwDesc_.dlcLightingCaps.dwSize = 16;
    hwDesc_.dlcLightingCaps.dwCaps = 7;
    hwDesc_.dlcLightingCaps.dwLightingModel = 1;
    hwDesc_.dlcLightingCaps.dwNumLights = 0;
    hwDesc_.dpcLineCaps.dwSize = 56;
    hwDesc_.dpcLineCaps.dwMiscCaps = 0x3FAC83;
    hwDesc_.dpcLineCaps.dwRasterCaps = 0xC7361B3;
    hwDesc_.dpcLineCaps.dwZCmpCaps = 0xFF;
    hwDesc_.dpcLineCaps.dwSrcBlendCaps = 0x1FFF;
    hwDesc_.dpcLineCaps.dwDestBlendCaps = 0x1FFF;
    hwDesc_.dpcLineCaps.dwAlphaCmpCaps = 0xFF;
    hwDesc_.dpcLineCaps.dwShadeCaps = 0xC528A;
    hwDesc_.dpcLineCaps.dwTextureCaps = 0x1EC4D;
    hwDesc_.dpcLineCaps.dwTextureFilterCaps = 0x703073F;
    hwDesc_.dpcLineCaps.dwTextureBlendCaps = 0xCF;
    hwDesc_.dpcLineCaps.dwTextureAddressCaps = 0x3F;
    hwDesc_.dpcLineCaps.dwStippleWidth = 0;
    hwDesc_.dpcLineCaps.dwStippleHeight = 0;
    hwDesc_.dpcTriCaps.dwSize = 56;
    hwDesc_.dpcTriCaps.dwMiscCaps = 0x3FACF3;
    hwDesc_.dpcTriCaps.dwRasterCaps = 0xC7361B3;
    hwDesc_.dpcTriCaps.dwZCmpCaps = 0xFF;
    hwDesc_.dpcTriCaps.dwSrcBlendCaps = 0x1FFF;
    hwDesc_.dpcTriCaps.dwDestBlendCaps = 0x1FFF;
    hwDesc_.dpcTriCaps.dwAlphaCmpCaps = 0xFF;
    hwDesc_.dpcTriCaps.dwShadeCaps = 0xC528A;
    hwDesc_.dpcTriCaps.dwTextureCaps = 0x1EC4D;
    hwDesc_.dpcTriCaps.dwTextureFilterCaps = 0x703073F;
    hwDesc_.dpcTriCaps.dwTextureBlendCaps = 0xCF;
    hwDesc_.dpcTriCaps.dwTextureAddressCaps = 0x3F;
    hwDesc_.dpcTriCaps.dwStippleWidth = 0;
    hwDesc_.dpcTriCaps.dwStippleHeight = 0;
    hwDesc_.dwDeviceRenderBitDepth = 1280;
    hwDesc_.dwDeviceZBufferBitDepth = 1024;
    hwDesc_.dwMaxBufferSize = 0;
    hwDesc_.dwMaxVertexCount = 1024;
    hwDesc_.dwMinTextureWidth = 1;
    hwDesc_.dwMinTextureHeight = 1;
    hwDesc_.dwMaxTextureWidth = 4096;
    hwDesc_.dwMaxTextureHeight = 4096;
    memset(&hwDesc_.dwMinStippleWidth, 0, 16);
    hwDesc_.dwMaxTextureRepeat = 0x2000;
    hwDesc_.dwMaxTextureAspectRatio = 0x2000;
    hwDesc_.dwMaxAnisotropy = 16;
    hwDesc_.dvGuardBandLeft = -32768.0;
    hwDesc_.dvGuardBandTop = -32768.0;
    hwDesc_.dvGuardBandRight = 32768.0;
    hwDesc_.dvGuardBandBottom = 32768.0;
    hwDesc_.dvExtentsAdjust = 0.0;
    hwDesc_.dwStencilCaps = 0xFF;
    hwDesc_.dwFVFCaps = 0x100008;
    hwDesc_.dwTextureOpCaps = 0x3FFFFFF;
    hwDesc_.wMaxTextureBlendStages = 8;
    hwDesc_.wMaxSimultaneousTextures = 8;
    if (hwDesc)
        memcpy(hwDesc, &hwDesc_, hwDesc->dwSize);

    D3DDEVICEDESC halDesc_;
    halDesc_.dwSize = sizeof(D3DDEVICEDESC);
    static_assert(sizeof(D3DDEVICEDESC) == 252);
    halDesc_.dwFlags = 31;
    halDesc_.dcmColorModel = 0;
    halDesc_.dwDevCaps = 1;
    halDesc_.dtcTransformCaps.dwSize = 8;
    halDesc_.dtcTransformCaps.dwCaps = 1;
    halDesc_.bClipping = 1;
    halDesc_.dlcLightingCaps.dwSize = 16;
    halDesc_.dlcLightingCaps.dwCaps = 15;
    halDesc_.dlcLightingCaps.dwLightingModel = 1;
    halDesc_.dlcLightingCaps.dwNumLights = 0;
    halDesc_.dpcLineCaps.dwSize = 56;
    memset(&halDesc_.dpcLineCaps.dwMiscCaps, 0, 52);
    halDesc_.dpcTriCaps.dwSize = 56;
    memset(&halDesc_.dpcTriCaps.dwMiscCaps, 0, 64);
    halDesc_.dwMaxVertexCount = 1024;
    memset(&halDesc_.dwMinTextureWidth, 0, 80);
    if (halDesc)
        memcpy(halDesc, &halDesc_, halDesc->dwSize);
    return 0;
}

HRESULT FakeDevice3::GetStats(LPD3DSTATS) {
    gog_debug("Unused function called: FakeDevice3::GetStats");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::AddViewport(LPDIRECT3DVIEWPORT3) {
    return DD_OK;
}

HRESULT FakeDevice3::DeleteViewport(LPDIRECT3DVIEWPORT3) {
    gog_debug("Unused function called: FakeDevice3::DeleteViewport");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::NextViewport(LPDIRECT3DVIEWPORT3, LPDIRECT3DVIEWPORT3 *, DWORD) {
    gog_debug("Unused function called: FakeDevice3::NextViewport");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::EnumTextureFormats(LPD3DENUMPIXELFORMATSCALLBACK cb, LPVOID a3) {
    DDPIXELFORMAT pixFormat;
    pixFormat.dwFourCC = 0;
    pixFormat.dwRGBAlphaBitMask = 0;
    pixFormat.dwSize = sizeof(DDPIXELFORMAT);
    static_assert(sizeof(DDPIXELFORMAT) == 32);
    pixFormat.dwFlags = 0x40;
    pixFormat.dwRGBBitCount = 32;
    pixFormat.dwBBitMask = 0xFF;
    pixFormat.dwGBitMask = 0xFF00;
    pixFormat.dwRBitMask = 0xFF0000;
    if (cb(&pixFormat, a3) != 1)
        return 0;
    pixFormat.dwSize = sizeof(DDPIXELFORMAT);
    pixFormat.dwFlags = 0x41;
    pixFormat.dwRGBBitCount = 32;
    pixFormat.dwBBitMask = 0xFF;
    pixFormat.dwGBitMask = 0xFF00;
    pixFormat.dwRBitMask = 0xFF0000;
    pixFormat.dwRGBAlphaBitMask = 0xFF000000;
    cb(&pixFormat, a3);
    return 0;
}

HRESULT FakeDevice3::BeginScene(void) {
    HRESULT hr;
    if (gog::g_isFlip) {
        D3DRECT rect;
        rect.x1 = 0;
        rect.y1 = 0;
        rect.x2 = gog::g_dwWidth;
        rect.y2 = gog::g_dwHeight;
        if (cfg::iAntialias && orig::pIDirectDrawSurface4_zbuf) {
            rect.x2 = gog::g_dwWidth * cfg::iAntialias;
            rect.y2 = gog::g_dwHeight * cfg::iAntialias;
        }
        hr = orig::pIDirect3DViewport3->Clear2(1, &rect, 2, 0xFF00FF00, 1.0, 0);
        if (FAILED(hr)) gog_debug("Assertion failed: FakeDevice3::BeginScene:837");
        g_isFlip = false;
    }
    if (orig::pIDirectDrawSurface4_zbuf) {
        IDirectDrawSurface4 *f88_orig_surf;
        if (g_isAntialiasGt10 && g_dwWidth == 640 && cfg::iAntialias > 1) {
            orig::pIDirectDrawSurface4_640x480->Blt(NULL, FakeSurface::instance_cpy->orig(), NULL, 0x1000000, NULL);
            f88_orig_surf = orig::pIDirectDrawSurface4_640x480;
        } else {
            f88_orig_surf = FakeSurface::instance_cpy->orig();
        }
        orig::pIDirectDrawSurface4_zbuf->Blt(NULL, f88_orig_surf, NULL, 0x1000000, NULL);
    }
    g_isSceneDrawing = true;
    hr = orig::pIDirect3DDevice3->BeginScene();
    if (FAILED(hr)) {
        gog_debugf("Assertion failed: FakeDevice3::BeginScene:849 with HRESULT 0x%x", hr);
        return hr;
    }
    return hr;
}

HRESULT FakeDevice3::EndScene(void) {
    HRESULT hr;
    g_isSceneDrawing = false;
    hr = orig::pIDirect3DDevice3->EndScene();
    if (FAILED(hr)) {
        gog_debugf("Assertion failed: FakeDevice3::EndScene:855 with HRESULT 0x%x", hr);
    }
    if (!orig::pIDirectDrawSurface4_zbuf)
        return hr;
    if (g_isAntialiasGt10 && g_dwWidth == 640 && cfg::iAntialias > 1) {
        orig::pIDirectDrawSurface4_640x480->Blt(NULL, orig::pIDirectDrawSurface4_zbuf, NULL, 0x1000000, NULL);
        FakeSurface::instance_cpy->orig()->Blt(NULL, orig::pIDirectDrawSurface4_640x480, NULL, 0x1000000, NULL);
        return hr;
    }
    FakeSurface::instance_cpy->orig()->Blt(NULL, orig::pIDirectDrawSurface4_zbuf, NULL, 0x1000000, NULL);
    return hr;
}

HRESULT FakeDevice3::GetDirect3D(LPDIRECT3D3 *) {
    gog_debug("Unused function called: FakeDevice3::GetDirect3D");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::SetCurrentViewport(LPDIRECT3DVIEWPORT3) {
    return DD_OK;
}

HRESULT FakeDevice3::GetCurrentViewport(LPDIRECT3DVIEWPORT3 *) {
    gog_debug("Unused function called: FakeDevice3::GetCurrentViewport");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::SetRenderTarget(LPDIRECTDRAWSURFACE4, DWORD) {
    gog_debug("Unused function called: FakeDevice3::SetRenderTarget");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::GetRenderTarget(LPDIRECTDRAWSURFACE4 *) {
    gog_debug("Unused function called: FakeDevice3::GetRenderTarget");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::Begin(D3DPRIMITIVETYPE, DWORD, DWORD) {
    gog_debug("Unused function called: FakeDevice3::Begin");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::BeginIndexed(D3DPRIMITIVETYPE, DWORD, LPVOID, DWORD, DWORD) {
    gog_debug("Unused function called: FakeDevice3::BeginIndexed");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::Vertex(LPVOID) {
    gog_debug("Unused function called: FakeDevice3::Vertex");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::Index(WORD) {
    gog_debug("Unused function called: FakeDevice3::Index");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::End(DWORD) {
    gog_debug("Unused function called: FakeDevice3::End");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::GetRenderState(D3DRENDERSTATETYPE, LPDWORD) {
    gog_debug("Unused function called: FakeDevice3::GetRenderState");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::SetRenderState(D3DRENDERSTATETYPE stateType, DWORD a3) {
    if (
            stateType == D3DRENDERSTATE_DITHERENABLE ||
            stateType == D3DRENDERSTATE_SUBPIXEL ||
            stateType == D3DRENDERSTATE_FOGENABLE
            )
        return 0;
    if (stateType == D3DRENDERSTATE_ANTIALIAS) gog_debug("Assertion failed: FakeDevice3::SetRenderState:879");
    HRESULT hr = orig::pIDirect3DDevice3->SetRenderState(stateType, a3);
    if (FAILED(hr)) {
        gog_debugf("Assertion failed: FakeDevice3::SetRenderState:887 with HRESULT 0x%x", hr);
    }
    return hr;
}

HRESULT FakeDevice3::GetLightState(D3DLIGHTSTATETYPE, LPDWORD) {
    gog_debug("Unused function called: FakeDevice3::GetLightState");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::SetLightState(D3DLIGHTSTATETYPE, DWORD) {
    gog_debug("Unused function called: FakeDevice3::SetLightState");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::SetTransform(D3DTRANSFORMSTATETYPE, LPD3DMATRIX) {
    gog_debug("Unused function called: FakeDevice3::SetTransform");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::GetTransform(D3DTRANSFORMSTATETYPE, LPD3DMATRIX) {
    gog_debug("Unused function called: FakeDevice3::GetTransform");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::MultiplyTransform(D3DTRANSFORMSTATETYPE, LPD3DMATRIX) {
    gog_debug("Unused function called: FakeDevice3::MultiplyTransform");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::DrawPrimitive(D3DPRIMITIVETYPE, DWORD, LPVOID, DWORD, DWORD) {
    gog_debug("Unused function called: FakeDevice3::DrawPrimitive");
    return DDERR_GENERIC;
}

namespace dk2 {

    struct Vertex2C {

        /*   0*/ float f0_x;
        /*   4*/ float f4_y;
        /*   8*/ float f8_z;
        /*   C*/ float fC_rhv__colorWeight;
        /*  10*/ int f10_diffuse;
        dk2::TexCoord f14_tex[3];
    };
    static_assert(sizeof(Vertex2C) == 0x2C);

}
#define Vertex1C_TypeDesc 0x144
#define Vertex2C_TypeDesc 0x344

HRESULT
FakeDevice3::DrawIndexedPrimitive(D3DPRIMITIVETYPE primitive_type, DWORD fvf, LPVOID vertices, DWORD vertex_count,
                                  LPWORD indices, DWORD index_count, DWORD flags) {
    if (!g_isSceneDrawing) gog_debug("Assertion failed: FakeDevice3::DrawIndexedPrimitive:914");
    if (primitive_type != D3DPT_TRIANGLELIST) gog_debug("Assertion failed: FakeDevice3::DrawIndexedPrimitive:915");
    if (cfg::iBumpmap) {
        if (fvf != Vertex1C_TypeDesc && fvf != Vertex2C_TypeDesc) gog_debug(
                "Assertion failed: FakeDevice3::DrawIndexedPrimitive:917");
    } else if (fvf != Vertex1C_TypeDesc) {
        gog_debug("Assertion failed: FakeDevice3::DrawIndexedPrimitive:919");
    }
    if (!vertices) gog_debug("Assertion failed: FakeDevice3::DrawIndexedPrimitive:921");
    if (!vertex_count) gog_debug("Assertion failed: FakeDevice3::DrawIndexedPrimitive:922");
    if (!indices) gog_debug("Assertion failed: FakeDevice3::DrawIndexedPrimitive:923");
    if (!index_count) gog_debug("Assertion failed: FakeDevice3::DrawIndexedPrimitive:924");
    if (flags != 0x1C) gog_debug("Assertion failed: FakeDevice3::DrawIndexedPrimitive:925");

    if (fvf == Vertex1C_TypeDesc) {
        if (vertex_count) {
            dk2::Vertex1C *pos = (dk2::Vertex1C *) vertices;
            int vertex_left = vertex_count;
            do {
                if (pos->z < 0.0 || pos->z > 1.0) gog_debug("Assertion failed: FakeDevice3::DrawIndexedPrimitive:929");
                ++pos;
                --vertex_left;
            } while (vertex_left);
        }
        if (cfg::iAntialias && orig::pIDirectDrawSurface4_zbuf) {
            unsigned int lastVertesIdx = 0;
            if (vertex_count >= 4) {
                unsigned int quadsLeft = ((unsigned int) (vertex_count - 4) >> 2) + 1;
                dk2::Vertex1C *quad = (dk2::Vertex1C *) vertices;
                double dAntialias = (float) cfg::iAntialias;
                lastVertesIdx = 4 * quadsLeft;
                do {
                    quad[0].x = dAntialias * quad[0].x;
                    quad[0].y = dAntialias * quad[0].y;
                    quad[1].x = dAntialias * quad[1].x;
                    quad[1].y = dAntialias * quad[1].y;
                    quad[2].x = dAntialias * quad[2].x;
                    quad[2].y = dAntialias * quad[2].y;
                    quad[3].x = dAntialias * quad[3].x;
                    quad[3].y = dAntialias * quad[3].y;
                    quad += 4;
                    --quadsLeft;
                } while (quadsLeft);
            }
            if (lastVertesIdx < vertex_count) {
                dk2::Vertex1C *vertex = ((dk2::Vertex1C *) vertices) + lastVertesIdx;
                double dAntialias = (float) cfg::iAntialias;
                unsigned int vertexLeft = vertex_count - lastVertesIdx;
                do {
                    vertex->x = dAntialias * vertex->x;
                    vertex->y = dAntialias * vertex->y;
                    ++vertex;
                    --vertexLeft;
                } while (vertexLeft);
            }
        }
    } else if (cfg::iAntialias && orig::pIDirectDrawSurface4_zbuf) {
        unsigned int lastVertexIdx = 0;
        if (vertex_count >= 4) {
            unsigned int quadsLeft = ((unsigned int) (vertex_count - 4) >> 2) + 1;
            dk2::Vertex2C *quad = (dk2::Vertex2C *) vertices;
            double dAntialias = (float) cfg::iAntialias;
            lastVertexIdx = 4 * quadsLeft;
            do {
                --quadsLeft;
                quad[0].f0_x = dAntialias * quad[0].f0_x;
                quad[0].f4_y = dAntialias * quad[0].f4_y;
                quad[1].f0_x = dAntialias * quad[1].f0_x;
                quad[1].f4_y = dAntialias * quad[1].f4_y;
                quad[2].f0_x = dAntialias * quad[2].f0_x;
                quad[2].f4_y = dAntialias * quad[2].f4_y;
                quad[3].f0_x = dAntialias * quad[3].f0_x;
                quad[3].f4_y = dAntialias * quad[3].f4_y;
                quad += 4;
            } while (quadsLeft);
        }
        if (lastVertexIdx < vertex_count) {
            double dAntialias = (float) cfg::iAntialias;
            dk2::Vertex2C *vertex = ((dk2::Vertex2C *) vertices) + lastVertexIdx;
            unsigned int vertexLeft = vertex_count - lastVertexIdx;
            do {
                vertex->f0_x = dAntialias * vertex->f0_x;
                vertex->f4_y = dAntialias * vertex->f4_y;
                ++vertex;
                --vertexLeft;
            } while (vertexLeft);
        }
    }
    HRESULT hr;
    hr = orig::pIDirect3DDevice3->DrawIndexedPrimitive(
            primitive_type, fvf, vertices, vertex_count, indices, index_count, 0x15
    );
    if (FAILED(hr)) {
        gog_debugf("Assertion failed: FakeDevice3::DrawIndexedPrimitive:951 with HRESULT 0x%x", hr);
        return hr;
    }
    return hr;
}

HRESULT FakeDevice3::SetClipStatus(LPD3DCLIPSTATUS) {
    gog_debug("Unused function called: FakeDevice3::SetClipStatus");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::GetClipStatus(LPD3DCLIPSTATUS) {
    gog_debug("Unused function called: FakeDevice3::GetClipStatus");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::DrawPrimitiveStrided(D3DPRIMITIVETYPE, DWORD, LPD3DDRAWPRIMITIVESTRIDEDDATA, DWORD, DWORD) {
    gog_debug("Unused function called: FakeDevice3::DrawPrimitiveStrided");
    return DDERR_GENERIC;
}

HRESULT
FakeDevice3::DrawIndexedPrimitiveStrided(D3DPRIMITIVETYPE, DWORD, LPD3DDRAWPRIMITIVESTRIDEDDATA, DWORD, LPWORD, DWORD,
                                         DWORD) {
    gog_debug("Unused function called: FakeDevice3::DrawIndexedPrimitiveStrided");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::DrawPrimitiveVB(D3DPRIMITIVETYPE, LPDIRECT3DVERTEXBUFFER, DWORD, DWORD, DWORD) {
    gog_debug("Unused function called: FakeDevice3::DrawPrimitiveVB");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::DrawIndexedPrimitiveVB(D3DPRIMITIVETYPE, LPDIRECT3DVERTEXBUFFER, LPWORD, DWORD, DWORD) {
    gog_debug("Unused function called: FakeDevice3::DrawIndexedPrimitiveVB");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::ComputeSphereVisibility(LPD3DVECTOR, LPD3DVALUE, DWORD, DWORD, LPDWORD) {
    gog_debug("Unused function called: FakeDevice3::ComputeSphereVisibility");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::GetTexture(DWORD, LPDIRECT3DTEXTURE2 *) {
    gog_debug("Unused function called: FakeDevice3::GetTexture");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::SetTexture(DWORD a3, LPDIRECT3DTEXTURE2 tex_) {
    auto *tex = (FakeTexture *) tex_;
    IDirect3DTexture2 *orig_tex = nullptr;
    if (tex) orig_tex = tex->orig();
    HRESULT hr = orig::pIDirect3DDevice3->SetTexture(a3, orig_tex);
    if (FAILED(hr)) {
        gog_debugf("Assertion failed: FakeDevice3::SetTexture:964 with HRESULT 0x%x", hr);
        return hr;
    }
    return hr;
}

HRESULT FakeDevice3::GetTextureStageState(DWORD, D3DTEXTURESTAGESTATETYPE, LPDWORD) {
    gog_debug("Unused function called: FakeDevice3::GetTextureStageState");
    return DDERR_GENERIC;
}

HRESULT FakeDevice3::SetTextureStageState(DWORD Stage, D3DTEXTURESTAGESTATETYPE Type, DWORD Value) {
    if (cfg::iBumpmap) {
        if (Stage != 0 && Stage != 1 && Stage != 2) gog_debug(
                "Assertion failed: FakeDevice3::SetTextureStageState:970");
    } else if (Stage != 0) {
        gog_debug("Assertion failed: FakeDevice3::SetTextureStageState:972");
    }
    switch (Type) {
        case D3DTSS_MAXANISOTROPY: gog_debug("Assertion failed: FakeDevice3::SetTextureStageState:975");
            break;
        case D3DTSS_MAGFILTER:
            if (Value == 2) Value = 5;
            break;
        case D3DTSS_MINFILTER:
            if (Value == 2) Value = 3;
            break;
        default:
            break;
    }
    HRESULT hr = orig::pIDirect3DDevice3->SetTextureStageState(Stage, Type, Value);
    if (FAILED(hr)) {
        gog_debugf("Assertion failed: FakeDevice3::SetTextureStageState:984 with HRESULT 0x%x", hr);
        return hr;
    }
    return hr;
}

HRESULT FakeDevice3::ValidateDevice(LPDWORD) {
    gog_debug("Unused function called: FakeDevice3::ValidateDevice");
    return DDERR_GENERIC;
}

