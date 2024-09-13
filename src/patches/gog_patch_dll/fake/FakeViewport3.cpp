//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeViewport3.h>
#include <gog_debug.h>

using namespace gog;

FakeViewport3 *FakeViewport3::instance = nullptr;

HRESULT FakeViewport3::QueryInterface(REFIID riid, LPVOID FAR *ppvObj) {
    gog_debug("Unused function called: FakeViewport3::QueryInterface");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::Initialize(LPDIRECT3D) {
    gog_debug("Unused function called: FakeViewport3::Initialize");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::GetViewport(LPD3DVIEWPORT) {
    gog_debug("Unused function called: FakeViewport3::GetViewport");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::SetViewport(LPD3DVIEWPORT) {
    gog_debug("Unused function called: FakeViewport3::SetViewport");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::TransformVertices(DWORD, LPD3DTRANSFORMDATA, DWORD, LPDWORD) {
    gog_debug("Unused function called: FakeViewport3::TransformVertices");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::LightElements(DWORD, LPD3DLIGHTDATA) {
    gog_debug("Unused function called: FakeViewport3::LightElements");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::SetBackground(D3DMATERIALHANDLE) {
    gog_debug("Unused function called: FakeViewport3::SetBackground");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::GetBackground(LPD3DMATERIALHANDLE, LPBOOL) {
    gog_debug("Unused function called: FakeViewport3::GetBackground");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::SetBackgroundDepth(LPDIRECTDRAWSURFACE) {
    gog_debug("Unused function called: FakeViewport3::SetBackgroundDepth");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::GetBackgroundDepth(LPDIRECTDRAWSURFACE *, LPBOOL) {
    gog_debug("Unused function called: FakeViewport3::GetBackgroundDepth");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::Clear(DWORD, LPD3DRECT, DWORD) {
    gog_debug("Unused function called: FakeViewport3::Clear");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::AddLight(LPDIRECT3DLIGHT) {
    gog_debug("Unused function called: FakeViewport3::AddLight");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::DeleteLight(LPDIRECT3DLIGHT) {
    gog_debug("Unused function called: FakeViewport3::DeleteLight");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::NextLight(LPDIRECT3DLIGHT, LPDIRECT3DLIGHT *, DWORD) {
    gog_debug("Unused function called: FakeViewport3::NextLight");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::GetViewport2(LPD3DVIEWPORT2) {
    gog_debug("Unused function called: FakeViewport3::GetViewport2");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::SetViewport2(LPD3DVIEWPORT2) {
    return DD_OK;
}

HRESULT FakeViewport3::SetBackgroundDepth2(LPDIRECTDRAWSURFACE4) {
    gog_debug("Unused function called: FakeViewport3::SetBackgroundDepth2");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::GetBackgroundDepth2(LPDIRECTDRAWSURFACE4 *, LPBOOL) {
    gog_debug("Unused function called: FakeViewport3::GetBackgroundDepth2");
    return DDERR_GENERIC;
}

HRESULT FakeViewport3::Clear2(DWORD, LPD3DRECT, DWORD, D3DCOLOR, D3DVALUE, DWORD) {
    gog_debug("Unused function called: FakeViewport3::Clear2");
    return DDERR_GENERIC;
}
