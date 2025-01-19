//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeD3D3.h>
#include <fake/FakeViewport3.h>
#include <fake/FakeSurface.h>
#include <fake/FakeDevice3.h>
#include <gog_globals.h>
#include <fake/FakeSurface4.h>
#include <gog_debug.h>

using namespace gog;

FakeD3D3 *FakeD3D3::instance = nullptr;

HRESULT FakeD3D3::QueryInterface(REFIID riid, LPVOID *ppvObj) {
    gog_debug("Unused function called: FakeD3D3::QueryInterface");
    return DDERR_GENERIC;
}

HRESULT FakeD3D3::EnumDevices(LPD3DENUMDEVICESCALLBACK, LPVOID) {
    gog_debug("Unused function called: FakeD3D3::EnumDevices");
    return DDERR_GENERIC;
}

HRESULT FakeD3D3::CreateLight(LPDIRECT3DLIGHT *, LPUNKNOWN) {
    gog_debug("Unused function called: FakeD3D3::CreateLight");
    return DDERR_GENERIC;
}

HRESULT FakeD3D3::CreateMaterial(LPDIRECT3DMATERIAL3 *, LPUNKNOWN) {
    gog_debug("Unused function called: FakeD3D3::CreateMaterial");
    return DDERR_GENERIC;
}

HRESULT FakeD3D3::CreateViewport(LPDIRECT3DVIEWPORT3 *a2, LPUNKNOWN a3) {
    if (a3 != nullptr) {
        gog_debug("Assertion failed: FakeD3D3::CreateViewport:1005");
    }
    *a2 = FakeViewport3::instance;
    return 0;
}

HRESULT FakeD3D3::FindDevice(LPD3DFINDDEVICESEARCH, LPD3DFINDDEVICERESULT) {
    gog_debug("Unused function called: FakeD3D3::FindDevice");
    return DDERR_GENERIC;
}

HRESULT FakeD3D3::CreateDevice(REFCLSID riid, LPDIRECTDRAWSURFACE4 surf_, LPDIRECT3DDEVICE3 *a4, LPUNKNOWN a5) {
    FakeSurface4 *surf = (FakeSurface4 *) surf_;
    if (!IsEqualGUID(IID_IDirect3DHALDevice, riid)) gog_debug("Assertion failed: FakeD3D3::CreateDevice:1011");
    if (!surf) gog_debug("Assertion failed: FakeD3D3::CreateDevice:1012");
    if (!a4) gog_debug("Assertion failed: FakeD3D3::CreateDevice:1013");
    if (a5) gog_debug("Assertion failed: FakeD3D3::CreateDevice:1014");
    if (surf->orig() != FakeSurface::instance_cpy->orig()) gog_debug("Assertion failed: FakeD3D3::CreateDevice:1015");
    if (orig::pIDirect3DDevice3) {
        gog_debug("Assertion failed: FakeD3D3::CreateDevice:1017");
    } else {
        LPDIRECTDRAWSURFACE4 orig_surf = orig::pIDirectDrawSurface4_zbuf;
        if (orig::pIDirectDrawSurface4_zbuf == nullptr) orig_surf = surf->orig();
        HRESULT hr = orig::pIDirect3D3->CreateDevice(riid, orig_surf, &orig::pIDirect3DDevice3, NULL);
        if (FAILED(hr)) {
            gog_debugf("Assertion failed: FakeD3D3::CreateDevice:1021 with HRESULT 0x%x", hr);
        }
    }
    *a4 = new FakeDevice3();
    return DD_OK;
}

HRESULT FakeD3D3::CreateVertexBuffer(LPD3DVERTEXBUFFERDESC, LPDIRECT3DVERTEXBUFFER *, DWORD, LPUNKNOWN) {
    gog_debug("Unused function called: FakeD3D3::CreateVertexBuffer");
    return DDERR_GENERIC;
}

HRESULT FakeD3D3::EnumZBufferFormats(REFCLSID, LPD3DENUMPIXELFORMATSCALLBACK, LPVOID) {
    gog_debug("Unused function called: FakeD3D3::EnumZBufferFormats");
    return DDERR_GENERIC;
}

HRESULT FakeD3D3::EvictManagedTextures(void) {
    gog_debug("Unused function called: FakeD3D3::EvictManagedTextures");
    return DDERR_GENERIC;
}
