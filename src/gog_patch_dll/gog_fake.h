//
// Created by DiaLight on 20.01.2023.
//

#ifndef EMBER_GOG_FAKE_H
#define EMBER_GOG_FAKE_H

#include <Windows.h>
#include <ddraw.h>

namespace gog {

    void fakeInit();

    LPDIRECTDRAWSURFACE4 Fake_CreateZBuf(DWORD width, DWORD height);
    void Fake_Redraw();
    void Fake_InitRenderRect();

}

#endif //EMBER_GOG_FAKE_H
