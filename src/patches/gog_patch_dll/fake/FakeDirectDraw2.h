//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_FAKEDIRECTDRAW2_H
#define EMBER_FAKEDIRECTDRAW2_H

#include <d3d.h>
#include <fake/FakeUnknown.h>

namespace gog {

    class FakeDirectDraw2 : public FakeUnknown<IDirectDraw2> {

    public:
        /*** IUnknown methods ***/
        STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID FAR * ppvObj) override;

        /*** IDirectDraw methods ***/
        STDMETHOD(Compact)(THIS) override;
        STDMETHOD(CreateClipper)(THIS_ DWORD, LPDIRECTDRAWCLIPPER FAR*, IUnknown FAR * ) override;
        STDMETHOD(CreatePalette)(THIS_ DWORD, LPPALETTEENTRY, LPDIRECTDRAWPALETTE FAR*, IUnknown FAR * ) override;
        STDMETHOD(CreateSurface)(THIS_  LPDDSURFACEDESC, LPDIRECTDRAWSURFACE FAR *, IUnknown FAR *) override;
        STDMETHOD(DuplicateSurface)( THIS_ LPDIRECTDRAWSURFACE, LPDIRECTDRAWSURFACE FAR * ) override;
        STDMETHOD(EnumDisplayModes)( THIS_ DWORD, LPDDSURFACEDESC, LPVOID, LPDDENUMMODESCALLBACK ) override;
        STDMETHOD(EnumSurfaces)(THIS_ DWORD, LPDDSURFACEDESC, LPVOID,LPDDENUMSURFACESCALLBACK ) override;
        STDMETHOD(FlipToGDISurface)(THIS) override;
        STDMETHOD(GetCaps)( THIS_ LPDDCAPS, LPDDCAPS) override;
        STDMETHOD(GetDisplayMode)( THIS_ LPDDSURFACEDESC) override;
        STDMETHOD(GetFourCCCodes)(THIS_  LPDWORD, LPDWORD ) override;
        STDMETHOD(GetGDISurface)(THIS_ LPDIRECTDRAWSURFACE FAR *) override;
        STDMETHOD(GetMonitorFrequency)(THIS_ LPDWORD) override;
        STDMETHOD(GetScanLine)(THIS_ LPDWORD) override;
        STDMETHOD(GetVerticalBlankStatus)(THIS_ LPBOOL ) override;
        STDMETHOD(Initialize)(THIS_ GUID FAR *) override;
        STDMETHOD(RestoreDisplayMode)(THIS) override;
        STDMETHOD(SetCooperativeLevel)(THIS_ HWND, DWORD) override;
        STDMETHOD(SetDisplayMode)(THIS_ DWORD, DWORD,DWORD, DWORD, DWORD) override;
        STDMETHOD(WaitForVerticalBlank)(THIS_ DWORD, HANDLE ) override;
        /*** Added in the v2 interface ***/
        STDMETHOD(GetAvailableVidMem)(THIS_ LPDDSCAPS, LPDWORD, LPDWORD) override;

        static FakeDirectDraw2 *instance;

    };

}

#endif //EMBER_FAKEDIRECTDRAW2_H
