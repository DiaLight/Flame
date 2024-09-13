//
// Created by DiaLight on 20.01.2023.
//
#include <fake/FakeTexture.h>
#include <gog_debug.h>

using namespace gog;

FakeTexture::FakeTexture(IDirect3DTexture2 *orig_tex) : f8_orig_tex(orig_tex) {}

HRESULT FakeTexture::QueryInterface(const IID &riid, LPVOID *ppvObj) {
    gog_debug("Unused function called: FakeTexture::QueryInterface");
    return DDERR_GENERIC;
}

ULONG FakeTexture::Release(void) {
    if (--this->refs != 0)
        return this->refs;
    if (this->f8_orig_tex) {
        this->f8_orig_tex->Release();
        this->f8_orig_tex = nullptr;
    }
    operator delete(this);
    return 0;
}

HRESULT FakeTexture::GetHandle(LPDIRECT3DDEVICE2, LPD3DTEXTUREHANDLE) {
    gog_debug("Unused function called: FakeTexture::GetHandle");
    return DDERR_GENERIC;
}

HRESULT FakeTexture::PaletteChanged(DWORD, DWORD) {
    gog_debug("Unused function called: FakeTexture::PaletteChanged");
    return DDERR_GENERIC;
}

HRESULT FakeTexture::Load(LPDIRECT3DTEXTURE2) {
    gog_debug("Unused function called: FakeTexture::Load");
    return DDERR_GENERIC;
}


