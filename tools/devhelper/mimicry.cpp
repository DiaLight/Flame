//
// Created by DiaLight on 16.08.2024.
//

#include "mimicry.h"
#include <Windows.h>
#include <dinput.h>
#include <ddraw.h>


typedef HRESULT (WINAPI *DirectDrawCreateProc)(GUID FAR *lpGUID, LPDIRECTDRAW FAR *lplpDD, IUnknown FAR *pUnkOuter);
DirectDrawCreateProc DirectDrawCreateOrig = nullptr;
#pragma comment(linker, "/EXPORT:DirectDrawCreate@12=DirectDrawCreate")
[[maybe_unused]] HRESULT WINAPI DirectDrawCreate(GUID FAR *lpGUID, LPDIRECTDRAW FAR *lplpDD, IUnknown FAR *pUnkOuter) {
    return DirectDrawCreateOrig(lpGUID, lplpDD, pUnkOuter);
}

typedef HRESULT (WINAPI *DirectDrawEnumerateAProc)(LPDDENUMCALLBACKA lpCallback, LPVOID lpContext);
DirectDrawEnumerateAProc DirectDrawEnumerateAOrig = nullptr;
#pragma comment(linker, "/EXPORT:DirectDrawEnumerateA@8=DirectDrawEnumerateA")
[[maybe_unused]] HRESULT WINAPI DirectDrawEnumerateA(LPDDENUMCALLBACKA lpCallback, LPVOID lpContext) {
    return DirectDrawEnumerateAOrig(lpCallback, lpContext);
}


bool initMimicry() {
    HMODULE ddraw = LoadLibraryA("DDRAW.dll");
    DirectDrawCreateOrig = (DirectDrawCreateProc) GetProcAddress(ddraw, "DirectDrawCreate");
    DirectDrawEnumerateAOrig = (DirectDrawEnumerateAProc) GetProcAddress(ddraw, "DirectDrawEnumerateA");
    if(!ddraw || !DirectDrawCreateOrig || !DirectDrawEnumerateAOrig) return false;
    return true;
}