//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeD3D.h>
#include <gog_debug.h>

using namespace gog;

FakeD3D *FakeD3D::instance = nullptr;

HRESULT FakeD3D::QueryInterface(REFIID riid, LPVOID *ppvObj) {
    gog_debug("Unused function called: FakeD3D::QueryInterface");
    return DDERR_GENERIC;
}

HRESULT FakeD3D::Initialize(REFCLSID) {
    gog_debug("Unused function called: FakeD3D::Initialize");
    return DDERR_GENERIC;
}

typedef struct _D3DDeviceDesc1 {
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
} D3DDEVICEDESC1, *LPD3DDEVICEDESC1;
static_assert(sizeof(D3DDEVICEDESC1) == 0xAC);
static_assert(sizeof(D3DDEVICEDESC) == 0xFC);

HRESULT FakeD3D::EnumDevices(LPD3DENUMDEVICESCALLBACK cb, LPVOID a3) {
    D3DDEVICEDESC rampDesc1;
    rampDesc1.dwSize = sizeof(D3DDEVICEDESC1);
    memset(&rampDesc1.dwFlags, 0, 0xC);
    rampDesc1.dtcTransformCaps.dwSize = 8;
    rampDesc1.dtcTransformCaps.dwCaps = 0;
    rampDesc1.bClipping = 0;
    rampDesc1.dlcLightingCaps.dwSize = 0x10;
    memset(&rampDesc1.dlcLightingCaps.dwCaps, 0, 0xC);
    rampDesc1.dpcLineCaps.dwSize = 0x38;
    memset(&rampDesc1.dpcLineCaps.dwMiscCaps, 0, 0x34);
    rampDesc1.dpcTriCaps.dwSize = 0x38;
    memset(&rampDesc1.dpcTriCaps.dwMiscCaps, 0, 0x44);


    D3DDEVICEDESC1 rampDesc2;
    rampDesc2.dwSize = sizeof(D3DDEVICEDESC1);
    rampDesc2.dwFlags = 0x7DF;
    rampDesc2.dcmColorModel = 1;
    rampDesc2.dwDevCaps = 0x55B;
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


    D3DDEVICEDESC1 rgbemuDesc1;
    rgbemuDesc1.dwSize = sizeof(D3DDEVICEDESC1);
    memset(&rgbemuDesc1.dwFlags, 0, 0xC);
    rgbemuDesc1.dtcTransformCaps.dwSize = 8;
    rgbemuDesc1.dtcTransformCaps.dwCaps = 0;
    rgbemuDesc1.bClipping = 0;
    rgbemuDesc1.dlcLightingCaps.dwSize = 0x10;
    memset(&rgbemuDesc1.dlcLightingCaps.dwCaps, 0, 0xC);
    rgbemuDesc1.dpcLineCaps.dwSize = 0x38;
    memset(&rgbemuDesc1.dpcLineCaps.dwMiscCaps, 0, 0x34);
    rgbemuDesc1.dpcTriCaps.dwSize = 0x38;
    memset(&rgbemuDesc1.dpcTriCaps.dwMiscCaps, 0, 0x44);


    D3DDEVICEDESC1 rgbemuDesc2;
    rgbemuDesc2.dwSize = sizeof(D3DDEVICEDESC1);
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


    D3DDEVICEDESC1 halDesc1;
    halDesc1.dwSize = sizeof(D3DDEVICEDESC1);
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


    D3DDEVICEDESC1 halDEsc2;
    halDEsc2.dwSize = sizeof(D3DDEVICEDESC1);
    halDEsc2.dwFlags = 0x1F;
    halDEsc2.dcmColorModel = 0;
    halDEsc2.dwDevCaps = 1;
    halDEsc2.dtcTransformCaps.dwSize = 8;
    halDEsc2.dtcTransformCaps.dwCaps = 1;
    halDEsc2.bClipping = 1;
    halDEsc2.dlcLightingCaps.dwSize = 0x10;
    halDEsc2.dlcLightingCaps.dwCaps = 0xF;
    halDEsc2.dlcLightingCaps.dwLightingModel = 1;
    halDEsc2.dlcLightingCaps.dwNumLights = 0;
    halDEsc2.dpcLineCaps.dwSize = 0x38;
    memset(&halDEsc2.dpcLineCaps.dwMiscCaps, 0, 0x34);
    halDEsc2.dpcTriCaps.dwSize = 0x38;
    memset(&halDEsc2.dpcTriCaps.dwMiscCaps, 0, 0x40);
    halDEsc2.dwMaxVertexCount = 0x400;


    D3DDEVICEDESC1 desc1;
    memcpy(&desc1, &rampDesc1, sizeof(D3DDEVICEDESC1));
    D3DDEVICEDESC desc2;
    memcpy(&desc2, &rampDesc2, sizeof(D3DDEVICEDESC1));
    GUID guid;
    guid = IID_IDirect3DRampDevice;
    if (cb(
            &guid,
            (LPSTR) "Microsoft Direct3D Mono(Ramp) Software Emulation",
            (LPSTR) "Ramp Emulation",
            (LPD3DDEVICEDESC) &desc1, &desc2, a3) != DD_FALSE)
        return DD_OK;
    memcpy(&desc1, &rgbemuDesc1, sizeof(D3DDEVICEDESC1));
    memcpy(&desc2, &rgbemuDesc2, sizeof(D3DDEVICEDESC1));
    guid = IID_IDirect3DRGBDevice;
    if (cb(
            &guid,
            (LPSTR) "Microsoft Direct3D RGB Software Emulation",
            (LPSTR) "RGB Emulation",
            (LPD3DDEVICEDESC) &desc1, &desc2, a3) != DD_FALSE)
        return DD_OK;
    memcpy(&desc1, &halDesc1, sizeof(D3DDEVICEDESC1));
    memcpy(&desc2, &halDEsc2, sizeof(D3DDEVICEDESC1));
    guid = IID_IDirect3DHALDevice;
    cb(
            &guid,
            (LPSTR) "Microsoft Direct3D Hardware acceleration through Direct3D HAL",
            (LPSTR) "Direct3D HAL",
            (LPD3DDEVICEDESC) &desc1, &desc2, a3);
    return DD_OK;
}

HRESULT FakeD3D::CreateLight(LPDIRECT3DLIGHT *, IUnknown *) {
    gog_debug("Unused function called: FakeD3D::CreateLight");
    return DDERR_GENERIC;
}

HRESULT FakeD3D::CreateMaterial(LPDIRECT3DMATERIAL *, IUnknown *) {
    gog_debug("Unused function called: FakeD3D::CreateMaterial");
    return DDERR_GENERIC;
}

HRESULT FakeD3D::CreateViewport(LPDIRECT3DVIEWPORT *, IUnknown *) {
    gog_debug("Unused function called: FakeD3D::CreateViewport");
    return DDERR_GENERIC;
}

HRESULT FakeD3D::FindDevice(LPD3DFINDDEVICESEARCH, LPD3DFINDDEVICERESULT) {
    gog_debug("Unused function called: FakeD3D::FindDevice");
    return DDERR_GENERIC;
}
