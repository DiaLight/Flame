//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_FAKETEXTURE_H
#define EMBER_FAKETEXTURE_H

#include <d3d.h>
#include <fake/FakeUnknown.h>

namespace gog {

    class FakeTexture : public FakeUnknown<IDirect3DTexture2> {
        IDirect3DTexture2 *f8_orig_tex;
    public:
        explicit FakeTexture(IDirect3DTexture2 *orig_tex);

        inline IDirect3DTexture2 *orig() { return f8_orig_tex; }

        /*** IUnknown methods ***/
        STDMETHOD(QueryInterface)(THIS_ REFIID riid, LPVOID * ppvObj) override;
        STDMETHOD_(ULONG,Release)(THIS) override;

        /*** IDirect3DTexture2 methods ***/
        STDMETHOD(GetHandle)(THIS_ LPDIRECT3DDEVICE2,LPD3DTEXTUREHANDLE) override;
        STDMETHOD(PaletteChanged)(THIS_ DWORD,DWORD) override;
        STDMETHOD(Load)(THIS_ LPDIRECT3DTEXTURE2) override;
    };

    static_assert(sizeof(FakeTexture) == 0xC);

}

#endif //EMBER_FAKETEXTURE_H
