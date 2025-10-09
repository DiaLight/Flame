//
// Created by DiaLight on 10/9/2025.
//

#ifndef FLAME_SHOW_WIREFRAME_H
#define FLAME_SHOW_WIREFRAME_H

#include <Windows.h>

typedef struct DIDEVICEOBJECTDATA DIDEVICEOBJECTDATA;

namespace patch::show_wireframe {

    void onKeyboard(DIDEVICEOBJECTDATA *data);
    void window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);

}


#endif // FLAME_SHOW_WIREFRAME_H
