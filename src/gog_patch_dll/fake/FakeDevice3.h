//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_FAKEDEVICE3_H
#define EMBER_FAKEDEVICE3_H

#include <d3d.h>
#include <fake/FakeUnknown.h>

namespace gog {

    class FakeDevice3 : public FakeUnknown<IDirect3DDevice3> {

    public:
        FakeDevice3();

        /*** IUnknown methods ***/
        STDMETHOD(QueryInterface)(THIS_ REFIID riid, LPVOID * ppvObj) override;
        STDMETHOD_(ULONG,Release)(THIS) override;

        /*** IDirect3DDevice3 methods ***/
        STDMETHOD(GetCaps)(THIS_ LPD3DDEVICEDESC,LPD3DDEVICEDESC) override;
        STDMETHOD(GetStats)(THIS_ LPD3DSTATS) override;
        STDMETHOD(AddViewport)(THIS_ LPDIRECT3DVIEWPORT3) override;
        STDMETHOD(DeleteViewport)(THIS_ LPDIRECT3DVIEWPORT3) override;
        STDMETHOD(NextViewport)(THIS_ LPDIRECT3DVIEWPORT3,LPDIRECT3DVIEWPORT3*,DWORD) override;
        STDMETHOD(EnumTextureFormats)(THIS_ LPD3DENUMPIXELFORMATSCALLBACK,LPVOID) override;
        STDMETHOD(BeginScene)(THIS) override;
        STDMETHOD(EndScene)(THIS) override;
        STDMETHOD(GetDirect3D)(THIS_ LPDIRECT3D3*) override;
        STDMETHOD(SetCurrentViewport)(THIS_ LPDIRECT3DVIEWPORT3) override;
        STDMETHOD(GetCurrentViewport)(THIS_ LPDIRECT3DVIEWPORT3 *) override;
        STDMETHOD(SetRenderTarget)(THIS_ LPDIRECTDRAWSURFACE4,DWORD) override;
        STDMETHOD(GetRenderTarget)(THIS_ LPDIRECTDRAWSURFACE4 *) override;
        STDMETHOD(Begin)(THIS_ D3DPRIMITIVETYPE,DWORD,DWORD) override;
        STDMETHOD(BeginIndexed)(THIS_ D3DPRIMITIVETYPE,DWORD,LPVOID,DWORD,DWORD) override;
        STDMETHOD(Vertex)(THIS_ LPVOID) override;
        STDMETHOD(Index)(THIS_ WORD) override;
        STDMETHOD(End)(THIS_ DWORD) override;
        STDMETHOD(GetRenderState)(THIS_ D3DRENDERSTATETYPE,LPDWORD) override;
        STDMETHOD(SetRenderState)(THIS_ D3DRENDERSTATETYPE,DWORD) override;
        STDMETHOD(GetLightState)(THIS_ D3DLIGHTSTATETYPE,LPDWORD) override;
        STDMETHOD(SetLightState)(THIS_ D3DLIGHTSTATETYPE,DWORD) override;
        STDMETHOD(SetTransform)(THIS_ D3DTRANSFORMSTATETYPE,LPD3DMATRIX) override;
        STDMETHOD(GetTransform)(THIS_ D3DTRANSFORMSTATETYPE,LPD3DMATRIX) override;
        STDMETHOD(MultiplyTransform)(THIS_ D3DTRANSFORMSTATETYPE,LPD3DMATRIX) override;
        STDMETHOD(DrawPrimitive)(THIS_ D3DPRIMITIVETYPE,DWORD,LPVOID,DWORD,DWORD) override;
        STDMETHOD(DrawIndexedPrimitive)(THIS_ D3DPRIMITIVETYPE,DWORD,LPVOID,DWORD,LPWORD,DWORD,DWORD) override;
        STDMETHOD(SetClipStatus)(THIS_ LPD3DCLIPSTATUS) override;
        STDMETHOD(GetClipStatus)(THIS_ LPD3DCLIPSTATUS) override;
        STDMETHOD(DrawPrimitiveStrided)(THIS_ D3DPRIMITIVETYPE,DWORD,LPD3DDRAWPRIMITIVESTRIDEDDATA,DWORD,DWORD) override;
        STDMETHOD(DrawIndexedPrimitiveStrided)(THIS_ D3DPRIMITIVETYPE,DWORD,LPD3DDRAWPRIMITIVESTRIDEDDATA,DWORD,LPWORD,DWORD,DWORD) override;
        STDMETHOD(DrawPrimitiveVB)(THIS_ D3DPRIMITIVETYPE,LPDIRECT3DVERTEXBUFFER,DWORD,DWORD,DWORD) override;
        STDMETHOD(DrawIndexedPrimitiveVB)(THIS_ D3DPRIMITIVETYPE,LPDIRECT3DVERTEXBUFFER,LPWORD,DWORD,DWORD) override;
        STDMETHOD(ComputeSphereVisibility)(THIS_ LPD3DVECTOR,LPD3DVALUE,DWORD,DWORD,LPDWORD) override;
        STDMETHOD(GetTexture)(THIS_ DWORD,LPDIRECT3DTEXTURE2 *) override;
        STDMETHOD(SetTexture)(THIS_ DWORD,LPDIRECT3DTEXTURE2) override;
        STDMETHOD(GetTextureStageState)(THIS_ DWORD,D3DTEXTURESTAGESTATETYPE,LPDWORD) override;
        STDMETHOD(SetTextureStageState)(THIS_ DWORD,D3DTEXTURESTAGESTATETYPE,DWORD) override;
        STDMETHOD(ValidateDevice)(THIS_ LPDWORD) override;

    };

    static_assert(sizeof(FakeDevice3) == 0x8);

}

#endif //EMBER_FAKEDEVICE3_H
