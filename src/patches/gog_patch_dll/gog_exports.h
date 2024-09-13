//
// Created by DiaLight on 21.01.2023.
//

#ifndef EMBER_GOG_EXPORTS_H
#define EMBER_GOG_EXPORTS_H

#include <ddraw.h>

extern "C" HRESULT WINAPI fake_DirectDrawCreate(GUID FAR *lpGUID, LPDIRECTDRAW FAR *lplpDD, IUnknown FAR *pUnkOuter);
extern "C" HRESULT WINAPI fake_DirectDrawEnumerateA(LPDDENUMCALLBACKA lpCallback, LPVOID lpContext);

#endif //EMBER_GOG_EXPORTS_H
