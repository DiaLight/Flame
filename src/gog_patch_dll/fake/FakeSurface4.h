//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_FAKESURFACE4_H
#define EMBER_FAKESURFACE4_H

#include <ddraw.h>
#include <fake/FakeUnknown.h>

namespace gog {

    class FakeSurface4 : public FakeUnknown<IDirectDrawSurface4> {
        LPDIRECTDRAWSURFACE4 f8_orig_surf;
        bool fC_isModSurf;
        ULONG f10_lockCounter;
        DDSURFACEDESC2 f14_desc;
    public:
        FakeSurface4(LPDIRECTDRAWSURFACE4 orig_surf, bool isModSurf);
        explicit FakeSurface4(LPDDSURFACEDESC2 pDesc);

        inline LPDIRECTDRAWSURFACE4 orig() { return f8_orig_surf; }

        /*** IUnknown methods ***/
        STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID FAR * ppvObj) override;
        STDMETHOD_(ULONG,Release) (THIS) override;

        /*** IDirectDrawSurface methods ***/
        STDMETHOD(AddAttachedSurface)(THIS_ LPDIRECTDRAWSURFACE4) override;
        STDMETHOD(AddOverlayDirtyRect)(THIS_ LPRECT) override;
        STDMETHOD(Blt)(THIS_ LPRECT,LPDIRECTDRAWSURFACE4, LPRECT,DWORD, LPDDBLTFX) override;
        STDMETHOD(BltBatch)(THIS_ LPDDBLTBATCH, DWORD, DWORD ) override;
        STDMETHOD(BltFast)(THIS_ DWORD,DWORD,LPDIRECTDRAWSURFACE4, LPRECT,DWORD) override;
        STDMETHOD(DeleteAttachedSurface)(THIS_ DWORD,LPDIRECTDRAWSURFACE4) override;
        STDMETHOD(EnumAttachedSurfaces)(THIS_ LPVOID,LPDDENUMSURFACESCALLBACK2) override;
        STDMETHOD(EnumOverlayZOrders)(THIS_ DWORD,LPVOID,LPDDENUMSURFACESCALLBACK2) override;
        STDMETHOD(Flip)(THIS_ LPDIRECTDRAWSURFACE4, DWORD) override;
        STDMETHOD(GetAttachedSurface)(THIS_ LPDDSCAPS2, LPDIRECTDRAWSURFACE4 FAR *) override;
        STDMETHOD(GetBltStatus)(THIS_ DWORD) override;
        STDMETHOD(GetCaps)(THIS_ LPDDSCAPS2) override;
        STDMETHOD(GetClipper)(THIS_ LPDIRECTDRAWCLIPPER FAR*) override;
        STDMETHOD(GetColorKey)(THIS_ DWORD, LPDDCOLORKEY) override;
        STDMETHOD(GetDC)(THIS_ HDC FAR *) override;
        STDMETHOD(GetFlipStatus)(THIS_ DWORD) override;
        STDMETHOD(GetOverlayPosition)(THIS_ LPLONG, LPLONG ) override;
        STDMETHOD(GetPalette)(THIS_ LPDIRECTDRAWPALETTE FAR*) override;
        STDMETHOD(GetPixelFormat)(THIS_ LPDDPIXELFORMAT) override;
        STDMETHOD(GetSurfaceDesc)(THIS_ LPDDSURFACEDESC2) override;
        STDMETHOD(Initialize)(THIS_ LPDIRECTDRAW, LPDDSURFACEDESC2) override;
        STDMETHOD(IsLost)(THIS) override;
        STDMETHOD(Lock)(THIS_ LPRECT,LPDDSURFACEDESC2,DWORD,HANDLE) override;
        STDMETHOD(ReleaseDC)(THIS_ HDC) override;
        STDMETHOD(Restore)(THIS) override;
        STDMETHOD(SetClipper)(THIS_ LPDIRECTDRAWCLIPPER) override;
        STDMETHOD(SetColorKey)(THIS_ DWORD, LPDDCOLORKEY) override;
        STDMETHOD(SetOverlayPosition)(THIS_ LONG, LONG ) override;
        STDMETHOD(SetPalette)(THIS_ LPDIRECTDRAWPALETTE) override;
        STDMETHOD(Unlock)(THIS_ LPRECT) override;
        STDMETHOD(UpdateOverlay)(THIS_ LPRECT, LPDIRECTDRAWSURFACE4,LPRECT,DWORD, LPDDOVERLAYFX) override;
        STDMETHOD(UpdateOverlayDisplay)(THIS_ DWORD) override;
        STDMETHOD(UpdateOverlayZOrder)(THIS_ DWORD, LPDIRECTDRAWSURFACE4) override;
        /*** Added in the v2 interface ***/
        STDMETHOD(GetDDInterface)(THIS_ LPVOID FAR *) override;
        STDMETHOD(PageLock)(THIS_ DWORD) override;
        STDMETHOD(PageUnlock)(THIS_ DWORD) override;
        /*** Added in the v3 interface ***/
        STDMETHOD(SetSurfaceDesc)(THIS_ LPDDSURFACEDESC2, DWORD) override;
        /*** Added in the v4 interface ***/
        STDMETHOD(SetPrivateData)(THIS_ REFGUID, LPVOID, DWORD, DWORD) override;
        STDMETHOD(GetPrivateData)(THIS_ REFGUID, LPVOID, LPDWORD) override;
        STDMETHOD(FreePrivateData)(THIS_ REFGUID) override;
        STDMETHOD(GetUniquenessValue)(THIS_ LPDWORD) override;
        STDMETHOD(ChangeUniquenessValue)(THIS) override;

    };

    static_assert(sizeof(FakeSurface4) == 0x90);

}

#endif //EMBER_FAKESURFACE4_H
