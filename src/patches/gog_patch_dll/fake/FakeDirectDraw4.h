//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_FAKEDIRECTDRAW4_H
#define EMBER_FAKEDIRECTDRAW4_H

#include <d3d.h>
#include <fake/FakeUnknown.h>

namespace gog {

    class FakeDirectDraw4 : public FakeUnknown<IDirectDraw4> {

    public:
        /*** IUnknown methods ***/
        STDMETHOD(QueryInterface) (THIS_ REFIID riid, LPVOID FAR * ppvObj) override;

        /*** IDirectDraw methods ***/
        STDMETHOD(Compact)(THIS) override;
        STDMETHOD(CreateClipper)(THIS_ DWORD, LPDIRECTDRAWCLIPPER FAR*, IUnknown FAR * ) override;
        STDMETHOD(CreatePalette)(THIS_ DWORD, LPPALETTEENTRY, LPDIRECTDRAWPALETTE FAR*, IUnknown FAR * ) override;
        STDMETHOD(CreateSurface)(THIS_  LPDDSURFACEDESC2, LPDIRECTDRAWSURFACE4 FAR *, IUnknown FAR *) override;
        STDMETHOD(DuplicateSurface)( THIS_ LPDIRECTDRAWSURFACE4, LPDIRECTDRAWSURFACE4 FAR * ) override;
        STDMETHOD(EnumDisplayModes)( THIS_ DWORD, LPDDSURFACEDESC2, LPVOID, LPDDENUMMODESCALLBACK2 ) override;
        STDMETHOD(EnumSurfaces)(THIS_ DWORD, LPDDSURFACEDESC2, LPVOID,LPDDENUMSURFACESCALLBACK2 ) override;
        STDMETHOD(FlipToGDISurface)(THIS) override;
        STDMETHOD(GetCaps)( THIS_ LPDDCAPS, LPDDCAPS) override;
        STDMETHOD(GetDisplayMode)( THIS_ LPDDSURFACEDESC2) override;
        STDMETHOD(GetFourCCCodes)(THIS_  LPDWORD, LPDWORD ) override;
        STDMETHOD(GetGDISurface)(THIS_ LPDIRECTDRAWSURFACE4 FAR *) override;
        STDMETHOD(GetMonitorFrequency)(THIS_ LPDWORD) override;
        STDMETHOD(GetScanLine)(THIS_ LPDWORD) override;
        STDMETHOD(GetVerticalBlankStatus)(THIS_ LPBOOL ) override;
        STDMETHOD(Initialize)(THIS_ GUID FAR *) override;
        STDMETHOD(RestoreDisplayMode)(THIS) override;
        STDMETHOD(SetCooperativeLevel)(THIS_ HWND, DWORD) override;
        STDMETHOD(SetDisplayMode)(THIS_ DWORD, DWORD,DWORD, DWORD, DWORD) override;
        STDMETHOD(WaitForVerticalBlank)(THIS_ DWORD, HANDLE ) override;
        /*** Added in the v2 interface ***/
        STDMETHOD(GetAvailableVidMem)(THIS_ LPDDSCAPS2, LPDWORD, LPDWORD) override;
        /*** Added in the V4 Interface ***/
        STDMETHOD(GetSurfaceFromDC) (THIS_ HDC, LPDIRECTDRAWSURFACE4 *) override;
        STDMETHOD(RestoreAllSurfaces)(THIS) override;
        STDMETHOD(TestCooperativeLevel)(THIS) override;
        STDMETHOD(GetDeviceIdentifier)(THIS_ LPDDDEVICEIDENTIFIER, DWORD ) override;

        static FakeDirectDraw4 *instance;

    };

}

#endif //EMBER_FAKEDIRECTDRAW4_H
