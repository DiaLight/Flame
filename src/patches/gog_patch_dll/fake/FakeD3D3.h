//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_FAKED3D3_H
#define EMBER_FAKED3D3_H

#include <d3d.h>
#include <fake/FakeUnknown.h>

namespace gog {

    class FakeD3D3 : public FakeUnknown<IDirect3D3> {

    public:

        static FakeD3D3 *instance;

        /*** IUnknown methods ***/
        STDMETHOD(QueryInterface)(THIS_ REFIID riid, LPVOID * ppvObj) override;

        /*** IDirect3D3 methods ***/
        STDMETHOD(EnumDevices)(THIS_ LPD3DENUMDEVICESCALLBACK,LPVOID) override;
        STDMETHOD(CreateLight)(THIS_ LPDIRECT3DLIGHT*,LPUNKNOWN) override;
        STDMETHOD(CreateMaterial)(THIS_ LPDIRECT3DMATERIAL3*,LPUNKNOWN) override;
        STDMETHOD(CreateViewport)(THIS_ LPDIRECT3DVIEWPORT3*,LPUNKNOWN) override;
        STDMETHOD(FindDevice)(THIS_ LPD3DFINDDEVICESEARCH,LPD3DFINDDEVICERESULT) override;
        STDMETHOD(CreateDevice)(THIS_ REFCLSID,LPDIRECTDRAWSURFACE4,LPDIRECT3DDEVICE3*,LPUNKNOWN) override;
        STDMETHOD(CreateVertexBuffer)(THIS_ LPD3DVERTEXBUFFERDESC,LPDIRECT3DVERTEXBUFFER*,DWORD,LPUNKNOWN) override;
        STDMETHOD(EnumZBufferFormats)(THIS_ REFCLSID,LPD3DENUMPIXELFORMATSCALLBACK,LPVOID) override;
        STDMETHOD(EvictManagedTextures)(THIS) override;

    };

}

#endif //EMBER_FAKED3D3_H
