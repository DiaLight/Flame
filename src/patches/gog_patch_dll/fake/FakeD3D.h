//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_FAKED3D_H
#define EMBER_FAKED3D_H

#include <d3d.h>
#include <fake/FakeUnknown.h>

namespace gog {

    class FakeD3D : public FakeUnknown<IDirect3D> {

    public:
        /*** IUnknown methods ***/
        STDMETHOD(QueryInterface)(THIS_ REFIID riid, LPVOID *ppvObj) override;

        /*** IDirect3D methods ***/
        STDMETHOD(Initialize)(THIS_ REFCLSID) override;
        STDMETHOD(EnumDevices)(THIS_ LPD3DENUMDEVICESCALLBACK, LPVOID) override;
        STDMETHOD(CreateLight)(THIS_ LPDIRECT3DLIGHT *, IUnknown *) override;
        STDMETHOD(CreateMaterial)(THIS_ LPDIRECT3DMATERIAL *, IUnknown *) override;
        STDMETHOD(CreateViewport)(THIS_ LPDIRECT3DVIEWPORT *, IUnknown *) override;
        STDMETHOD(FindDevice)(THIS_ LPD3DFINDDEVICESEARCH, LPD3DFINDDEVICERESULT) override;

        static FakeD3D *instance;

    };

}

#endif //EMBER_FAKED3D_H
