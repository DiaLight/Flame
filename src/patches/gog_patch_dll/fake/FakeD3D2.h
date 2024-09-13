//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_FAKED3D2_H
#define EMBER_FAKED3D2_H

#include <d3d.h>
#include <fake/FakeUnknown.h>

namespace gog {

    class FakeD3D2 : public FakeUnknown<IDirect3D2> {

    public:
        /*** IUnknown methods ***/
        STDMETHOD(QueryInterface)(THIS_ REFIID riid, LPVOID * ppvObj) override;

        /*** IDirect3D2 methods ***/
        STDMETHOD(EnumDevices)(THIS_ LPD3DENUMDEVICESCALLBACK,LPVOID) override;
        STDMETHOD(CreateLight)(THIS_ LPDIRECT3DLIGHT*,IUnknown*) override;
        STDMETHOD(CreateMaterial)(THIS_ LPDIRECT3DMATERIAL2*,IUnknown*) override;
        STDMETHOD(CreateViewport)(THIS_ LPDIRECT3DVIEWPORT2*,IUnknown*) override;
        STDMETHOD(FindDevice)(THIS_ LPD3DFINDDEVICESEARCH,LPD3DFINDDEVICERESULT) override;
        STDMETHOD(CreateDevice)(THIS_ REFCLSID,LPDIRECTDRAWSURFACE,LPDIRECT3DDEVICE2*) override;

        static FakeD3D2 *instance;

    };

}

#endif //EMBER_FAKED3D2_H
