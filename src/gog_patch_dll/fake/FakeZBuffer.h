//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_FAKEZBUFFER_H
#define EMBER_FAKEZBUFFER_H

#include <ddraw.h>
#include <fake/FakeUnknown.h>

namespace gog {

    class FakeZBuffer : public FakeUnknown<IDirectDrawSurface> {

    public:
        /*** IUnknown methods ***/
        STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID FAR * ppvObj) override;

        /*** IDirectDrawSurface methods ***/
        STDMETHOD(AddAttachedSurface)(THIS_ LPDIRECTDRAWSURFACE) override;
        STDMETHOD(AddOverlayDirtyRect)(THIS_ LPRECT) override;
        STDMETHOD(Blt)(THIS_ LPRECT,LPDIRECTDRAWSURFACE, LPRECT,DWORD, LPDDBLTFX) override;
        STDMETHOD(BltBatch)(THIS_ LPDDBLTBATCH, DWORD, DWORD ) override;
        STDMETHOD(BltFast)(THIS_ DWORD,DWORD,LPDIRECTDRAWSURFACE, LPRECT,DWORD) override;
        STDMETHOD(DeleteAttachedSurface)(THIS_ DWORD,LPDIRECTDRAWSURFACE) override;
        STDMETHOD(EnumAttachedSurfaces)(THIS_ LPVOID,LPDDENUMSURFACESCALLBACK) override;
        STDMETHOD(EnumOverlayZOrders)(THIS_ DWORD,LPVOID,LPDDENUMSURFACESCALLBACK) override;
        STDMETHOD(Flip)(THIS_ LPDIRECTDRAWSURFACE, DWORD) override;
        STDMETHOD(GetAttachedSurface)(THIS_ LPDDSCAPS, LPDIRECTDRAWSURFACE FAR *) override;
        STDMETHOD(GetBltStatus)(THIS_ DWORD) override;
        STDMETHOD(GetCaps)(THIS_ LPDDSCAPS) override;
        STDMETHOD(GetClipper)(THIS_ LPDIRECTDRAWCLIPPER FAR*) override;
        STDMETHOD(GetColorKey)(THIS_ DWORD, LPDDCOLORKEY) override;
        STDMETHOD(GetDC)(THIS_ HDC FAR *) override;
        STDMETHOD(GetFlipStatus)(THIS_ DWORD) override;
        STDMETHOD(GetOverlayPosition)(THIS_ LPLONG, LPLONG ) override;
        STDMETHOD(GetPalette)(THIS_ LPDIRECTDRAWPALETTE FAR*) override;
        STDMETHOD(GetPixelFormat)(THIS_ LPDDPIXELFORMAT) override;
        STDMETHOD(GetSurfaceDesc)(THIS_ LPDDSURFACEDESC) override;
        STDMETHOD(Initialize)(THIS_ LPDIRECTDRAW, LPDDSURFACEDESC) override;
        STDMETHOD(IsLost)(THIS) override;
        STDMETHOD(Lock)(THIS_ LPRECT,LPDDSURFACEDESC,DWORD,HANDLE) override;
        STDMETHOD(ReleaseDC)(THIS_ HDC) override;
        STDMETHOD(Restore)(THIS) override;
        STDMETHOD(SetClipper)(THIS_ LPDIRECTDRAWCLIPPER) override;
        STDMETHOD(SetColorKey)(THIS_ DWORD, LPDDCOLORKEY) override;
        STDMETHOD(SetOverlayPosition)(THIS_ LONG, LONG ) override;
        STDMETHOD(SetPalette)(THIS_ LPDIRECTDRAWPALETTE) override;
        STDMETHOD(Unlock)(THIS_ LPVOID) override;
        STDMETHOD(UpdateOverlay)(THIS_ LPRECT, LPDIRECTDRAWSURFACE,LPRECT,DWORD, LPDDOVERLAYFX) override;
        STDMETHOD(UpdateOverlayDisplay)(THIS_ DWORD) override;
        STDMETHOD(UpdateOverlayZOrder)(THIS_ DWORD, LPDIRECTDRAWSURFACE) override;

        static FakeZBuffer *instance;

    };

}

#endif //EMBER_FAKEZBUFFER_H
