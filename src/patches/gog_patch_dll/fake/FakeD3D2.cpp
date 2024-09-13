//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeD3D2.h>
#include <gog_debug.h>

using namespace gog;


FakeD3D2 *FakeD3D2::instance = nullptr;

HRESULT FakeD3D2::QueryInterface(const IID &riid, LPVOID *ppvObj) {
    gog_debug("Unused function called: FakeD3D2::QueryInterface");
    return DDERR_GENERIC;
}

typedef struct _D3DDeviceDesc2 {
    DWORD dwSize;                 /* Size of D3DDEVICEDESC2 structure */
    DWORD dwFlags;                /* Indicates which fields have valid data */
    D3DCOLORMODEL dcmColorModel;          /* Color model of device */
    DWORD dwDevCaps;              /* Capabilities of device */
    D3DTRANSFORMCAPS dtcTransformCaps;       /* Capabilities of transform */
    BOOL bClipping;              /* Device can do 3D clipping */
    D3DLIGHTINGCAPS dlcLightingCaps;        /* Capabilities of lighting */
    D3DPRIMCAPS dpcLineCaps;
    D3DPRIMCAPS dpcTriCaps;
    DWORD dwDeviceRenderBitDepth; /* One of DDBB_8, 16, etc.. */
    DWORD dwDeviceZBufferBitDepth;/* One of DDBD_16, 32, etc.. */
    DWORD dwMaxBufferSize;        /* Maximum execute buffer size */
    DWORD dwMaxVertexCount;       /* Maximum vertex count */
#if(DIRECT3D_VERSION >= 0x0500)
    // *** New fields for DX5 *** //

    // Width and height caps are 0 for legacy HALs.
    DWORD dwMinTextureWidth, dwMinTextureHeight;
    DWORD dwMaxTextureWidth, dwMaxTextureHeight;
    DWORD dwMinStippleWidth, dwMaxStippleWidth;
    DWORD dwMinStippleHeight, dwMaxStippleHeight;
#endif /* DIRECT3D_VERSION >= 0x0500 */
} D3DDEVICEDESC2, *LPD3DDEVICEDESC2;
static_assert(sizeof(D3DDEVICEDESC2) == 0xCC);
static_assert(sizeof(D3DDEVICEDESC) == 0xFC);

HRESULT FakeD3D2::EnumDevices(LPD3DENUMDEVICESCALLBACK cb, LPVOID a3) {
    D3DDEVICEDESC2 rampDesc2;
    rampDesc2.dwSize = sizeof(D3DDEVICEDESC2);
    rampDesc2.dwFlags = 0x7DF;
    rampDesc2.dcmColorModel = 1;
    rampDesc2.dwDevCaps = 1371;
    rampDesc2.dtcTransformCaps.dwSize = 8;
    rampDesc2.dtcTransformCaps.dwCaps = 1;
    rampDesc2.bClipping = 1;
    rampDesc2.dlcLightingCaps.dwSize = 0x10;
    rampDesc2.dlcLightingCaps.dwCaps = 0xF;
    rampDesc2.dlcLightingCaps.dwLightingModel = 2;
    rampDesc2.dlcLightingCaps.dwNumLights = 0;
    rampDesc2.dpcLineCaps.dwSize = 0x38;
    rampDesc2.dpcLineCaps.dwMiscCaps = 0x70;
    rampDesc2.dpcLineCaps.dwRasterCaps = 0x51;
    rampDesc2.dpcLineCaps.dwZCmpCaps = 0xFF;
    memset(&rampDesc2.dpcLineCaps.dwSrcBlendCaps, 0, 0xC);
    rampDesc2.dpcLineCaps.dwShadeCaps = 0xA145;
    rampDesc2.dpcLineCaps.dwTextureCaps = 0xB;
    rampDesc2.dpcLineCaps.dwTextureFilterCaps = 5;
    rampDesc2.dpcLineCaps.dwTextureBlendCaps = 0x42;
    rampDesc2.dpcLineCaps.dwTextureAddressCaps = 1;
    rampDesc2.dpcLineCaps.dwStippleWidth = 4;
    rampDesc2.dpcLineCaps.dwStippleHeight = 4;
    rampDesc2.dpcTriCaps.dwSize = 0x38;
    rampDesc2.dpcTriCaps.dwMiscCaps = 0x70;
    rampDesc2.dpcTriCaps.dwRasterCaps = 0x51;
    rampDesc2.dpcTriCaps.dwZCmpCaps = 0xFF;
    memset(&rampDesc2.dpcTriCaps.dwSrcBlendCaps, 0, 0xC);
    rampDesc2.dpcTriCaps.dwShadeCaps = 0xA145;
    rampDesc2.dpcTriCaps.dwTextureCaps = 0xB;
    rampDesc2.dpcTriCaps.dwTextureFilterCaps = 5;
    rampDesc2.dpcTriCaps.dwTextureBlendCaps = 0x42;
    rampDesc2.dpcTriCaps.dwTextureAddressCaps = 1;
    rampDesc2.dpcTriCaps.dwStippleWidth = 4;
    rampDesc2.dpcTriCaps.dwStippleHeight = 4;
    rampDesc2.dwDeviceRenderBitDepth = 0xF00;
    rampDesc2.dwDeviceZBufferBitDepth = 0x400;
    rampDesc2.dwMaxBufferSize = 0;
    rampDesc2.dwMaxVertexCount = 2021;
    memset(&rampDesc2.dwMinTextureWidth, 0, 0x20);


    D3DDEVICEDESC2 rgbemuDesc1;
    rgbemuDesc1.dwSize = sizeof(D3DDEVICEDESC2);
    memset(&rgbemuDesc1.dwFlags, 0, 0xC);
    rgbemuDesc1.dtcTransformCaps.dwSize = 8;
    rgbemuDesc1.dtcTransformCaps.dwCaps = 0;
    rgbemuDesc1.bClipping = 0;
    rgbemuDesc1.dlcLightingCaps.dwSize = 0x10;
    memset(&rgbemuDesc1.dlcLightingCaps.dwCaps, 0, 0xC);
    rgbemuDesc1.dpcLineCaps.dwSize = 0x38;
    memset(&rgbemuDesc1.dpcLineCaps.dwMiscCaps, 0, 0x34);
    rgbemuDesc1.dpcTriCaps.dwSize = 0x38;
    memset(&rgbemuDesc1.dpcTriCaps.dwMiscCaps, 0, 0x64);


    D3DDEVICEDESC2 rgbemuDesc2;
    rgbemuDesc2.dwSize = sizeof(D3DDEVICEDESC2);
    rgbemuDesc2.dwFlags = 0x7DF;
    rgbemuDesc2.dcmColorModel = 2;
    rgbemuDesc2.dwDevCaps = 0x55B;
    rgbemuDesc2.dtcTransformCaps.dwSize = 8;
    rgbemuDesc2.dtcTransformCaps.dwCaps = 1;
    rgbemuDesc2.bClipping = 1;
    rgbemuDesc2.dlcLightingCaps.dwSize = 0x10;
    rgbemuDesc2.dlcLightingCaps.dwCaps = 0xF;
    rgbemuDesc2.dlcLightingCaps.dwLightingModel = 1;
    rgbemuDesc2.dlcLightingCaps.dwNumLights = 0;
    rgbemuDesc2.dpcLineCaps.dwSize = 0x38;
    rgbemuDesc2.dpcLineCaps.dwMiscCaps = 0x70;
    rgbemuDesc2.dpcLineCaps.dwRasterCaps = 0x1D1;
    rgbemuDesc2.dpcLineCaps.dwZCmpCaps = 0xFF;
    memset(&rgbemuDesc2.dpcLineCaps.dwSrcBlendCaps, 0, 0xC);
    rgbemuDesc2.dpcLineCaps.dwShadeCaps = 0xCA28A;
    rgbemuDesc2.dpcLineCaps.dwTextureCaps = 0xB;
    rgbemuDesc2.dpcLineCaps.dwTextureFilterCaps = 0x1F;
    rgbemuDesc2.dpcLineCaps.dwTextureBlendCaps = 0x42;
    rgbemuDesc2.dpcLineCaps.dwTextureAddressCaps = 1;
    rgbemuDesc2.dpcLineCaps.dwStippleWidth = 4;
    rgbemuDesc2.dpcLineCaps.dwStippleHeight = 4;
    rgbemuDesc2.dpcTriCaps.dwSize = 0x38;
    rgbemuDesc2.dpcTriCaps.dwMiscCaps = 0x70;
    rgbemuDesc2.dpcTriCaps.dwRasterCaps = 0x1D1;
    rgbemuDesc2.dpcTriCaps.dwZCmpCaps = 0xFF;
    memset(&rgbemuDesc2.dpcTriCaps.dwSrcBlendCaps, 0, 0xC);
    rgbemuDesc2.dpcTriCaps.dwShadeCaps = 0xCA28A;
    rgbemuDesc2.dpcTriCaps.dwTextureCaps = 0xB;
    rgbemuDesc2.dpcTriCaps.dwTextureFilterCaps = 0x1F;
    rgbemuDesc2.dpcTriCaps.dwTextureBlendCaps = 0x42;
    rgbemuDesc2.dpcTriCaps.dwTextureAddressCaps = 1;
    rgbemuDesc2.dpcTriCaps.dwStippleWidth = 4;
    rgbemuDesc2.dpcTriCaps.dwStippleHeight = 4;
    rgbemuDesc2.dwDeviceRenderBitDepth = 0xF00;
    rgbemuDesc2.dwDeviceZBufferBitDepth = 0x400;
    rgbemuDesc2.dwMaxBufferSize = 0;
    rgbemuDesc2.dwMaxVertexCount = 2021;
    memset(&rgbemuDesc2.dwMinTextureWidth, 0, 0x20);


    D3DDEVICEDESC2 halDesc1;
    halDesc1.dwSize = sizeof(D3DDEVICEDESC2);
    halDesc1.dwFlags = 0x1FF;
    halDesc1.dcmColorModel = 2;
    halDesc1.dwDevCaps = 0x61BBEF1;
    halDesc1.dtcTransformCaps.dwSize = 8;
    halDesc1.dtcTransformCaps.dwCaps = 1;
    halDesc1.bClipping = 1;
    halDesc1.dlcLightingCaps.dwSize = 0x10;
    halDesc1.dlcLightingCaps.dwCaps = 7;
    halDesc1.dlcLightingCaps.dwLightingModel = 1;
    halDesc1.dlcLightingCaps.dwNumLights = 0;
    halDesc1.dpcLineCaps.dwSize = 0x38;
    halDesc1.dpcLineCaps.dwMiscCaps = 0x3FAC83;
    halDesc1.dpcLineCaps.dwRasterCaps = 0xC7361B3;
    halDesc1.dpcLineCaps.dwZCmpCaps = 0xFF;
    halDesc1.dpcLineCaps.dwSrcBlendCaps = 0x1FFF;
    halDesc1.dpcLineCaps.dwDestBlendCaps = 0x1FFF;
    halDesc1.dpcLineCaps.dwAlphaCmpCaps = 0xFF;
    halDesc1.dpcLineCaps.dwShadeCaps = 0xC528A;
    halDesc1.dpcLineCaps.dwTextureCaps = 0x1EC4D;
    halDesc1.dpcLineCaps.dwTextureFilterCaps = 0x703073F;
    halDesc1.dpcLineCaps.dwTextureBlendCaps = 0xCF;
    halDesc1.dpcLineCaps.dwTextureAddressCaps = 0x3F;
    halDesc1.dpcLineCaps.dwStippleWidth = 0;
    halDesc1.dpcLineCaps.dwStippleHeight = 0;
    halDesc1.dpcTriCaps.dwSize = 0x38;
    halDesc1.dpcTriCaps.dwMiscCaps = 0x3FACF3;
    halDesc1.dpcTriCaps.dwRasterCaps = 0xC7361B3;
    halDesc1.dpcTriCaps.dwZCmpCaps = 0xFF;
    halDesc1.dpcTriCaps.dwSrcBlendCaps = 0x1FFF;
    halDesc1.dpcTriCaps.dwDestBlendCaps = 0x1FFF;
    halDesc1.dpcTriCaps.dwAlphaCmpCaps = 0xFF;
    halDesc1.dpcTriCaps.dwShadeCaps = 0xC528A;
    halDesc1.dpcTriCaps.dwTextureCaps = 0x1EC4D;
    halDesc1.dpcTriCaps.dwTextureFilterCaps = 0x703073F;
    halDesc1.dpcTriCaps.dwTextureBlendCaps = 0xCF;
    halDesc1.dpcTriCaps.dwTextureAddressCaps = 0x3F;
    halDesc1.dpcTriCaps.dwStippleWidth = 0;
    halDesc1.dpcTriCaps.dwStippleHeight = 0;
    halDesc1.dwDeviceRenderBitDepth = 0x500;
    halDesc1.dwDeviceZBufferBitDepth = 0x400;
    halDesc1.dwMaxBufferSize = 0;
    halDesc1.dwMaxVertexCount = 0x400;
    halDesc1.dwMinTextureWidth = 1;
    halDesc1.dwMinTextureHeight = 1;
    halDesc1.dwMaxTextureWidth = 0x1000;
    halDesc1.dwMaxTextureHeight = 0x1000;
    memset(&halDesc1.dwMinStippleWidth, 0, 0x10);


    D3DDEVICEDESC2 halDesc2;
    halDesc2.dwSize = 204;
    halDesc2.dwFlags = 31;
    halDesc2.dcmColorModel = 0;
    halDesc2.dwDevCaps = 1;
    halDesc2.dtcTransformCaps.dwSize = 8;
    halDesc2.dtcTransformCaps.dwCaps = 1;
    halDesc2.bClipping = 1;
    halDesc2.dlcLightingCaps.dwSize = 0x10;
    halDesc2.dlcLightingCaps.dwCaps = 0xF;
    halDesc2.dlcLightingCaps.dwLightingModel = 1;
    halDesc2.dlcLightingCaps.dwNumLights = 0;
    halDesc2.dpcLineCaps.dwSize = 0x38;
    memset(&halDesc2.dpcLineCaps.dwMiscCaps, 0, 0x34);
    halDesc2.dpcTriCaps.dwSize = 0x38;
    memset(&halDesc2.dpcTriCaps.dwMiscCaps, 0, 0x40);
    halDesc2.dwMaxVertexCount = 0x400;
    memset(&halDesc2.dwMinTextureWidth, 0, 0x20);


    D3DDEVICEDESC2 nnxDesc1;
    nnxDesc1.dwSize = sizeof(D3DDEVICEDESC2);
    memset(&nnxDesc1.dwFlags, 0, 0xC);
    nnxDesc1.dtcTransformCaps.dwSize = 8;
    nnxDesc1.dtcTransformCaps.dwCaps = 0;
    nnxDesc1.bClipping = 0;
    nnxDesc1.dlcLightingCaps.dwSize = 0x10;
    memset(&nnxDesc1.dlcLightingCaps.dwCaps, 0, 0xC);
    nnxDesc1.dpcLineCaps.dwSize = 0x38;
    memset(&nnxDesc1.dpcLineCaps.dwMiscCaps, 0, 0x34);
    nnxDesc1.dpcTriCaps.dwSize = 0x38;
    memset(&nnxDesc1.dpcTriCaps.dwMiscCaps, 0, 0x64);


    D3DDEVICEDESC2 mmxDesc2;
    mmxDesc2.dwSize = sizeof(D3DDEVICEDESC2);
    mmxDesc2.dwFlags = 0x7DF;
    mmxDesc2.dcmColorModel = 2;
    mmxDesc2.dwDevCaps = 0x55B;
    mmxDesc2.dtcTransformCaps.dwSize = 8;
    mmxDesc2.dtcTransformCaps.dwCaps = 1;
    mmxDesc2.bClipping = 1;
    mmxDesc2.dlcLightingCaps.dwSize = 0x10;
    mmxDesc2.dlcLightingCaps.dwCaps = 0xF;
    mmxDesc2.dlcLightingCaps.dwLightingModel = 1;
    mmxDesc2.dlcLightingCaps.dwNumLights = 0;
    mmxDesc2.dpcLineCaps.dwSize = 0x38;
    mmxDesc2.dpcLineCaps.dwMiscCaps = 0x70;
    mmxDesc2.dpcLineCaps.dwRasterCaps = 0x1D1;
    mmxDesc2.dpcLineCaps.dwZCmpCaps = 0xFF;
    memset(&mmxDesc2.dpcLineCaps.dwSrcBlendCaps, 0, 0xC);
    mmxDesc2.dpcLineCaps.dwShadeCaps = 0xCA28A;
    mmxDesc2.dpcLineCaps.dwTextureCaps = 0xB;
    mmxDesc2.dpcLineCaps.dwTextureFilterCaps = 0x1F;
    mmxDesc2.dpcLineCaps.dwTextureBlendCaps = 0x42;
    mmxDesc2.dpcLineCaps.dwTextureAddressCaps = 1;
    mmxDesc2.dpcLineCaps.dwStippleWidth = 4;
    mmxDesc2.dpcLineCaps.dwStippleHeight = 4;
    mmxDesc2.dpcTriCaps.dwSize = 0x38;
    mmxDesc2.dpcTriCaps.dwMiscCaps = 0x70;
    mmxDesc2.dpcTriCaps.dwRasterCaps = 0x1D1;
    mmxDesc2.dpcTriCaps.dwZCmpCaps = 0xFF;
    memset(&mmxDesc2.dpcTriCaps.dwSrcBlendCaps, 0, 0xC);
    mmxDesc2.dpcTriCaps.dwShadeCaps = 0xCA28A;
    mmxDesc2.dpcTriCaps.dwTextureCaps = 0xB;
    mmxDesc2.dpcTriCaps.dwTextureFilterCaps = 0x1F;
    mmxDesc2.dpcTriCaps.dwTextureBlendCaps = 0x42;
    mmxDesc2.dpcTriCaps.dwTextureAddressCaps = 1;
    mmxDesc2.dpcTriCaps.dwStippleWidth = 4;
    mmxDesc2.dpcTriCaps.dwStippleHeight = 4;
    mmxDesc2.dwDeviceRenderBitDepth = 0xF00;
    mmxDesc2.dwDeviceZBufferBitDepth = 0x400;
    mmxDesc2.dwMaxBufferSize = 0;
    mmxDesc2.dwMaxVertexCount = 2021;
    memset(&mmxDesc2.dwMinTextureWidth, 0, 0x20);


    D3DDEVICEDESC2 rampDesc1;
    rampDesc1.dwSize = sizeof(D3DDEVICEDESC2);
    memset(&rampDesc1.dwFlags, 0, 0xC);
    rampDesc1.dtcTransformCaps.dwSize = 8;
    rampDesc1.dtcTransformCaps.dwCaps = 0;
    rampDesc1.bClipping = 0;
    rampDesc1.dlcLightingCaps.dwSize = 0x10;
    memset(&rampDesc1.dlcLightingCaps.dwCaps, 0, 0xC);
    rampDesc1.dpcLineCaps.dwSize = 0x38;
    memset(&rampDesc1.dpcLineCaps.dwMiscCaps, 0, 0x34);
    rampDesc1.dpcTriCaps.dwSize = 0x38;
    memset(&rampDesc1.dpcTriCaps.dwMiscCaps, 0, 0x64);


    D3DDEVICEDESC2 desc1;
    memcpy(&desc1, &rampDesc1, sizeof(D3DDEVICEDESC2));
    D3DDEVICEDESC desc2;
    memcpy(&desc2, &rampDesc2, sizeof(D3DDEVICEDESC2));
    GUID guid;
    guid = IID_IDirect3DRampDevice;
    if (cb(
            &guid,
            (LPSTR) "Microsoft Direct3D Mono(Ramp) Software Emulation",
            (LPSTR) "Ramp Emulation",
            (LPD3DDEVICEDESC) &desc1, &desc2, a3) != DD_FALSE)
        return DD_OK;

    memcpy(&desc1, &rgbemuDesc1, sizeof(D3DDEVICEDESC2));
    memcpy(&desc2, &rgbemuDesc2, sizeof(D3DDEVICEDESC2));
    guid = IID_IDirect3DRGBDevice;
    if (cb(
            &guid,
            (LPSTR) "Microsoft Direct3D RGB Software Emulation",
            (LPSTR) "RGB Emulation",
            (LPD3DDEVICEDESC) &desc1, &desc2, a3) != DD_FALSE)
        return DD_OK;

    memcpy(&desc1, &halDesc1, sizeof(D3DDEVICEDESC2));
    memcpy(&desc2, &halDesc2, sizeof(D3DDEVICEDESC2));
    guid = IID_IDirect3DHALDevice;
    if (cb(
            &guid,
            (LPSTR) "Microsoft Direct3D Hardware acceleration through Direct3D HAL",
            (LPSTR) "Direct3D HAL",
            (LPD3DDEVICEDESC) &desc1, &desc2, a3) != DD_FALSE)
        return DD_OK;

    memcpy(&desc1, &nnxDesc1, sizeof(D3DDEVICEDESC2));
    memcpy(&desc2, &mmxDesc2, sizeof(D3DDEVICEDESC2));
    guid = IID_IDirect3DMMXDevice;
    cb(
            &guid,
            (LPSTR) "Microsoft Direct3D MMX Software Emulation",
            (LPSTR) "MMX Emulation",
            (LPD3DDEVICEDESC) &desc1, &desc2, a3);
    return DD_OK;
}

HRESULT FakeD3D2::CreateLight(LPDIRECT3DLIGHT *, IUnknown *) {
    gog_debug("Unused function called: FakeD3D2::CreateLight");
    return DDERR_GENERIC;
}

HRESULT FakeD3D2::CreateMaterial(LPDIRECT3DMATERIAL2 *, IUnknown *) {
    gog_debug("Unused function called: FakeD3D2::CreateMaterial");
    return DDERR_GENERIC;
}

HRESULT FakeD3D2::CreateViewport(LPDIRECT3DVIEWPORT2 *, IUnknown *) {
    gog_debug("Unused function called: FakeD3D2::CreateViewport");
    return DDERR_GENERIC;
}

HRESULT FakeD3D2::FindDevice(LPD3DFINDDEVICESEARCH, LPD3DFINDDEVICERESULT) {
    gog_debug("Unused function called: FakeD3D2::FindDevice");
    return DDERR_GENERIC;
}

HRESULT FakeD3D2::CreateDevice(REFCLSID, LPDIRECTDRAWSURFACE, LPDIRECT3DDEVICE2 *) {
    gog_debug("Unused function called: FakeD3D2::CreateDevice");
    return DDERR_GENERIC;
}
