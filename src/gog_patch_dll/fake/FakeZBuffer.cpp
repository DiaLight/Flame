//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeZBuffer.h>
#include <gog_debug.h>

using namespace gog;


FakeZBuffer *FakeZBuffer::instance = nullptr;

HRESULT FakeZBuffer::QueryInterface(REFIID riid, LPVOID FAR *ppvObj) {
    gog_debug("Unused function called: FakeZBuffer::QueryInterface");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::AddAttachedSurface(LPDIRECTDRAWSURFACE) {
    gog_debug("Unused function called: FakeZBuffer::AddAttachedSurface");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::AddOverlayDirtyRect(LPRECT) {
    gog_debug("Unused function called: FakeZBuffer::AddOverlayDirtyRect");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::Blt(LPRECT, LPDIRECTDRAWSURFACE a3, LPRECT, DWORD, LPDDBLTFX) {
    if (a3) gog_debug("Assertion failed: FakeZBuffer::Blt:24");
    return DD_OK;
}

HRESULT FakeZBuffer::BltBatch(LPDDBLTBATCH, DWORD, DWORD) {
    gog_debug("Unused function called: FakeZBuffer::BltBatch");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::BltFast(DWORD, DWORD, LPDIRECTDRAWSURFACE, LPRECT, DWORD) {
    gog_debug("Unused function called: FakeZBuffer::BltFast");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::DeleteAttachedSurface(DWORD, LPDIRECTDRAWSURFACE) {
    gog_debug("Unused function called: FakeZBuffer::DeleteAttachedSurface");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::EnumAttachedSurfaces(LPVOID, LPDDENUMSURFACESCALLBACK) {
    gog_debug("Unused function called: FakeZBuffer::EnumAttachedSurfaces");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::EnumOverlayZOrders(DWORD, LPVOID, LPDDENUMSURFACESCALLBACK) {
    gog_debug("Unused function called: FakeZBuffer::EnumOverlayZOrders");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::Flip(LPDIRECTDRAWSURFACE, DWORD) {
    gog_debug("Unused function called: FakeZBuffer::Flip");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetAttachedSurface(LPDDSCAPS, LPDIRECTDRAWSURFACE *) {
    gog_debug("Unused function called: FakeZBuffer::GetAttachedSurface");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetBltStatus(DWORD) {
    gog_debug("Unused function called: FakeZBuffer::GetBltStatus");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetCaps(LPDDSCAPS) {
    gog_debug("Unused function called: FakeZBuffer::GetCaps");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetClipper(LPDIRECTDRAWCLIPPER *) {
    gog_debug("Unused function called: FakeZBuffer::GetClipper");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetColorKey(DWORD, LPDDCOLORKEY) {
    gog_debug("Unused function called: FakeZBuffer::GetColorKey");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetDC(HDC *) {
    gog_debug("Unused function called: FakeZBuffer::GetDC");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetFlipStatus(DWORD) {
    gog_debug("Unused function called: FakeZBuffer::GetFlipStatus");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetOverlayPosition(LPLONG, LPLONG) {
    gog_debug("Unused function called: FakeZBuffer::GetOverlayPosition");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetPalette(LPDIRECTDRAWPALETTE *) {
    gog_debug("Unused function called: FakeZBuffer::GetPalette");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetPixelFormat(LPDDPIXELFORMAT) {
    gog_debug("Unused function called: FakeZBuffer::GetPixelFormat");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::GetSurfaceDesc(LPDDSURFACEDESC) {
    gog_debug("Unused function called: FakeZBuffer::GetSurfaceDesc");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::Initialize(LPDIRECTDRAW, LPDDSURFACEDESC) {
    gog_debug("Unused function called: FakeZBuffer::Initialize");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::IsLost(void) {
    return DD_OK;
}

HRESULT FakeZBuffer::Lock(LPRECT, LPDDSURFACEDESC, DWORD, HANDLE) {
    gog_debug("Unused function called: FakeZBuffer::Lock");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::ReleaseDC(HDC) {
    gog_debug("Unused function called: FakeZBuffer::ReleaseDC");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::Restore(void) {
    return DD_OK;
}

HRESULT FakeZBuffer::SetClipper(LPDIRECTDRAWCLIPPER) {
    return DD_OK;
}

HRESULT FakeZBuffer::SetColorKey(DWORD, LPDDCOLORKEY) {
    gog_debug("Unused function called: FakeZBuffer::SetColorKey");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::SetOverlayPosition(LONG, LONG) {
    gog_debug("Unused function called: FakeZBuffer::SetOverlayPosition");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::SetPalette(LPDIRECTDRAWPALETTE) {
    gog_debug("Unused function called: FakeZBuffer::SetPalette");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::Unlock(LPVOID) {
    gog_debug("Unused function called: FakeZBuffer::Unlock");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::UpdateOverlay(LPRECT, LPDIRECTDRAWSURFACE, LPRECT, DWORD, LPDDOVERLAYFX) {
    gog_debug("Unused function called: FakeZBuffer::UpdateOverlay");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::UpdateOverlayDisplay(DWORD) {
    gog_debug("Unused function called: FakeZBuffer::UpdateOverlayDisplay");
    return DDERR_GENERIC;
}

HRESULT FakeZBuffer::UpdateOverlayZOrder(DWORD, LPDIRECTDRAWSURFACE) {
    gog_debug("Unused function called: FakeZBuffer::UpdateOverlayZOrder");
    return DDERR_GENERIC;
}

