//
// Created by DiaLight on 1/10/2026.
//

#ifndef FLAME_DDMODELIST_H
#define FLAME_DDMODELIST_H

#include <Windows.h>
#include <cstdint>
#include <ddraw.h>

namespace dk2 {

    struct DdModeListItem {
        DdModeListItem*next;
        DdModeListItem*prev;
        uint32_t dwWidth;
        uint32_t dwHeight;
        uint32_t dwRGBBitCount;
    };

    struct DdModeList {
        DdModeListItem*next;
        DdModeListItem*prev;
        DdModeListItem*last;

        void constructor();

        DdModeListItem*head();

        DdModeListItem*insert(DdModeListItem*_last, DdModeListItem*newItem);

        void destroy();
        bool callback(LPDDSURFACEDESC lpDesc);
        int *collect(int *pstatus, LPDIRECTDRAW lpDD, int useWindowContext, HWND hWnd);

        static DdModeList instance;

    };

}


#endif // FLAME_DDMODELIST_H
