//
// Created by DiaLight on 21.01.2023.
//
#include <ddraw.h>
#include <fake/FakeDirectDraw1.h>
#include <fake/FakeDirectDraw2.h>
#include <fake/FakeDirectDraw4.h>
#include <fake/FakeD3D3.h>
#include <gog_globals.h>
#include <gog_debug.h>

using namespace gog;

//#pragma comment(linker, "/EXPORT:DirectDrawCreate@12=DirectDrawCreate")
extern "C" HRESULT WINAPI fake_DirectDrawCreate(GUID FAR *lpGUID, LPDIRECTDRAW FAR *lplpDD, IUnknown FAR *pUnkOuter) {
    gog_debug("Creating DX device");
    if (lpGUID != nullptr) gog_debug("Assertion failed: FakeDirectDrawCreate:1517");
    if (lplpDD == nullptr) gog_debug("Assertion failed: FakeDirectDrawCreate:1518");
    if (!orig::pIDirectDraw4) {
        LPDIRECTDRAW lpDD;
        HRESULT hr = DirectDrawCreate(NULL, &lpDD, NULL);
        if (FAILED(hr))
            return hr;
        hr = lpDD->QueryInterface(IID_IDirectDraw4, (LPVOID *) &orig::pIDirectDraw4);
        if (FAILED(hr))
            return hr;
        lpDD->Release();
        FakeDirectDraw1::instance = new FakeDirectDraw1();
        FakeDirectDraw2::instance = new FakeDirectDraw2();
        FakeDirectDraw4::instance = new FakeDirectDraw4();
        FakeD3D3::instance = new FakeD3D3();
    }
    *lplpDD = FakeDirectDraw1::instance;
    return 0;
}

//#pragma comment(linker, "/EXPORT:DirectDrawEnumerateA@8=DirectDrawEnumerateA")
extern "C" HRESULT WINAPI fake_DirectDrawEnumerateA(LPDDENUMCALLBACKA lpCallback, LPVOID lpContext) {
    lpCallback(NULL, (LPSTR) "GOG HW Patch", (LPSTR) "GOG HW Patch", lpContext);
    return 0;
}