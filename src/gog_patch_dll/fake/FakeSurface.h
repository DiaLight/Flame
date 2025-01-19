//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_FAKESURFACE_H
#define EMBER_FAKESURFACE_H

#include <ddraw.h>
#include <fake/FakeUnknown.h>
#include <cstdint>

namespace gog {

    class FakeSurface : public FakeUnknown<IDirectDrawSurface2> {
        DDSURFACEDESC2 f8_surfDesc;
        bool f84_isModSurf;
        LPDIRECTDRAWSURFACE4 f88_orig_surf;
        RECT f8C_lockedRect;
        LPRECT f9C_pLockedRect;
    public:
        explicit FakeSurface(IDirectDrawSurface4 *orig_surf);
        explicit FakeSurface(DDSURFACEDESC2 *desc);

        inline LPDIRECTDRAWSURFACE4 orig() { return f88_orig_surf; }

        /*** IUnknown methods ***/
        STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID FAR * ppvObj) override;
        STDMETHOD_(ULONG,Release) (THIS) override;

        /*** IDirectDrawSurface methods ***/
        STDMETHOD(AddAttachedSurface)(THIS_ LPDIRECTDRAWSURFACE2) override;
        STDMETHOD(AddOverlayDirtyRect)(THIS_ LPRECT) override;
        STDMETHOD(Blt)(THIS_ LPRECT,LPDIRECTDRAWSURFACE2, LPRECT,DWORD, LPDDBLTFX) override;
        STDMETHOD(BltBatch)(THIS_ LPDDBLTBATCH, DWORD, DWORD ) override;
        STDMETHOD(BltFast)(THIS_ DWORD,DWORD,LPDIRECTDRAWSURFACE2, LPRECT,DWORD) override;
        STDMETHOD(DeleteAttachedSurface)(THIS_ DWORD,LPDIRECTDRAWSURFACE2) override;
        STDMETHOD(EnumAttachedSurfaces)(THIS_ LPVOID,LPDDENUMSURFACESCALLBACK) override;
        STDMETHOD(EnumOverlayZOrders)(THIS_ DWORD,LPVOID,LPDDENUMSURFACESCALLBACK) override;
        STDMETHOD(Flip)(THIS_ LPDIRECTDRAWSURFACE2, DWORD) override;
        STDMETHOD(GetAttachedSurface)(THIS_ LPDDSCAPS, LPDIRECTDRAWSURFACE2 FAR *) override;
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
        STDMETHOD(UpdateOverlay)(THIS_ LPRECT, LPDIRECTDRAWSURFACE2,LPRECT,DWORD, LPDDOVERLAYFX) override;
        STDMETHOD(UpdateOverlayDisplay)(THIS_ DWORD) override;
        STDMETHOD(UpdateOverlayZOrder)(THIS_ DWORD, LPDIRECTDRAWSURFACE2) override;
        /*** Added in the v2 interface ***/
        STDMETHOD(GetDDInterface)(THIS_ LPVOID FAR *) override;
        STDMETHOD(PageLock)(THIS_ DWORD) override;
        STDMETHOD(PageUnlock)(THIS_ DWORD) override;

        static FakeSurface *instance_mod;
        static FakeSurface *instance_cpy;
    };
    static_assert(sizeof(FakeSurface) == 0xA0);

}

#endif //EMBER_FAKESURFACE_H
