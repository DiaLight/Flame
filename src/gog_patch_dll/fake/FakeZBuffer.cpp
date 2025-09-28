//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeZBuffer.h>
#include <gog_debug.h>

using namespace gog;


FakeZBuffer *FakeZBuffer::instance = nullptr;

HRESULT FakeZBuffer::QueryInterface(REFIID riid, LPVOID FAR *ppvObj) {
    gog_unused_function_called("FakeZBuffer::QueryInterface");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::AddAttachedSurface(LPDIRECTDRAWSURFACE) {
    gog_unused_function_called("FakeZBuffer::AddAttachedSurface");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::AddOverlayDirtyRect(LPRECT) {
    gog_unused_function_called("FakeZBuffer::AddOverlayDirtyRect");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::Blt(LPRECT, LPDIRECTDRAWSURFACE a3, LPRECT, DWORD, LPDDBLTFX) {
    if (a3) gog_assert_failed("FakeZBuffer::Blt:24");
    return DD_OK;
}

HRESULT FakeZBuffer::BltBatch(LPDDBLTBATCH, DWORD, DWORD) {
    gog_unused_function_called("FakeZBuffer::BltBatch");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::BltFast(DWORD, DWORD, LPDIRECTDRAWSURFACE, LPRECT, DWORD) {
    gog_unused_function_called("FakeZBuffer::BltFast");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::DeleteAttachedSurface(DWORD, LPDIRECTDRAWSURFACE) {
    gog_unused_function_called("FakeZBuffer::DeleteAttachedSurface");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::EnumAttachedSurfaces(LPVOID, LPDDENUMSURFACESCALLBACK) {
    gog_unused_function_called("FakeZBuffer::EnumAttachedSurfaces");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::EnumOverlayZOrders(DWORD, LPVOID, LPDDENUMSURFACESCALLBACK) {
    gog_unused_function_called("FakeZBuffer::EnumOverlayZOrders");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::Flip(LPDIRECTDRAWSURFACE, DWORD) {
    gog_unused_function_called("FakeZBuffer::Flip");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetAttachedSurface(LPDDSCAPS, LPDIRECTDRAWSURFACE *) {
    gog_unused_function_called("FakeZBuffer::GetAttachedSurface");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetBltStatus(DWORD) {
    gog_unused_function_called("FakeZBuffer::GetBltStatus");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetCaps(LPDDSCAPS) {
    gog_unused_function_called("FakeZBuffer::GetCaps");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetClipper(LPDIRECTDRAWCLIPPER *) {
    gog_unused_function_called("FakeZBuffer::GetClipper");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetColorKey(DWORD, LPDDCOLORKEY) {
    gog_unused_function_called("FakeZBuffer::GetColorKey");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetDC(HDC *) {
    gog_unused_function_called("FakeZBuffer::GetDC");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetFlipStatus(DWORD) {
    gog_unused_function_called("FakeZBuffer::GetFlipStatus");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetOverlayPosition(LPLONG, LPLONG) {
    gog_unused_function_called("FakeZBuffer::GetOverlayPosition");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetPalette(LPDIRECTDRAWPALETTE *) {
    gog_unused_function_called("FakeZBuffer::GetPalette");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetPixelFormat(LPDDPIXELFORMAT) {
    gog_unused_function_called("FakeZBuffer::GetPixelFormat");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetSurfaceDesc(LPDDSURFACEDESC) {
    gog_unused_function_called("FakeZBuffer::GetSurfaceDesc");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::Initialize(LPDIRECTDRAW, LPDDSURFACEDESC) {
    gog_unused_function_called("FakeZBuffer::Initialize");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::IsLost(void) {
    return DD_OK;
}

HRESULT FakeZBuffer::Lock(LPRECT, LPDDSURFACEDESC, DWORD, HANDLE) {
    gog_unused_function_called("FakeZBuffer::Lock");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::ReleaseDC(HDC) {
    gog_unused_function_called("FakeZBuffer::ReleaseDC");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::Restore(void) {
    return DD_OK;
}

HRESULT FakeZBuffer::SetClipper(LPDIRECTDRAWCLIPPER) {
    return DD_OK;
}

HRESULT FakeZBuffer::SetColorKey(DWORD, LPDDCOLORKEY) {
    gog_unused_function_called("FakeZBuffer::SetColorKey");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::SetOverlayPosition(LONG, LONG) {
    gog_unused_function_called("FakeZBuffer::SetOverlayPosition");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::SetPalette(LPDIRECTDRAWPALETTE) {
    gog_unused_function_called("FakeZBuffer::SetPalette");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::Unlock(LPVOID) {
    gog_unused_function_called("FakeZBuffer::Unlock");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::UpdateOverlay(LPRECT, LPDIRECTDRAWSURFACE, LPRECT, DWORD, LPDDOVERLAYFX) {
    gog_unused_function_called("FakeZBuffer::UpdateOverlay");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::UpdateOverlayDisplay(DWORD) {
    gog_unused_function_called("FakeZBuffer::UpdateOverlayDisplay");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::UpdateOverlayZOrder(DWORD, LPDIRECTDRAWSURFACE) {
    gog_unused_function_called("FakeZBuffer::UpdateOverlayZOrder");
    return DDERR_GENERIC;
}

