//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_FAKEVIEWPORT3_H
#define EMBER_FAKEVIEWPORT3_H

#include <d3d.h>
#include <fake/FakeUnknown.h>

namespace gog {

    class FakeViewport3 : public FakeUnknown<IDirect3DViewport3> {

    public:
        /*** IUnknown methods ***/
        STDMETHOD(QueryInterface)(THIS_ REFIID riid, LPVOID * ppvObj) override;

        /*** IDirect3DViewport2 methods ***/
        STDMETHOD(Initialize)(THIS_ LPDIRECT3D) override;
        STDMETHOD(GetViewport)(THIS_ LPD3DVIEWPORT) override;
        STDMETHOD(SetViewport)(THIS_ LPD3DVIEWPORT) override;
        STDMETHOD(TransformVertices)(THIS_ DWORD,LPD3DTRANSFORMDATA,DWORD,LPDWORD) override;
        STDMETHOD(LightElements)(THIS_ DWORD,LPD3DLIGHTDATA) override;
        STDMETHOD(SetBackground)(THIS_ D3DMATERIALHANDLE) override;
        STDMETHOD(GetBackground)(THIS_ LPD3DMATERIALHANDLE,LPBOOL) override;
        STDMETHOD(SetBackgroundDepth)(THIS_ LPDIRECTDRAWSURFACE) override;
        STDMETHOD(GetBackgroundDepth)(THIS_ LPDIRECTDRAWSURFACE*,LPBOOL) override;
        STDMETHOD(Clear)(THIS_ DWORD,LPD3DRECT,DWORD) override;
        STDMETHOD(AddLight)(THIS_ LPDIRECT3DLIGHT) override;
        STDMETHOD(DeleteLight)(THIS_ LPDIRECT3DLIGHT) override;
        STDMETHOD(NextLight)(THIS_ LPDIRECT3DLIGHT,LPDIRECT3DLIGHT*,DWORD) override;
        STDMETHOD(GetViewport2)(THIS_ LPD3DVIEWPORT2) override;
        STDMETHOD(SetViewport2)(THIS_ LPD3DVIEWPORT2) override;
        STDMETHOD(SetBackgroundDepth2)(THIS_ LPDIRECTDRAWSURFACE4) override;
        STDMETHOD(GetBackgroundDepth2)(THIS_ LPDIRECTDRAWSURFACE4*,LPBOOL) override;
        STDMETHOD(Clear2)(THIS_ DWORD,LPD3DRECT,DWORD,D3DCOLOR,D3DVALUE,DWORD) override;

        static FakeViewport3 *instance;

    };

}

#endif //EMBER_FAKEVIEWPORT3_H
