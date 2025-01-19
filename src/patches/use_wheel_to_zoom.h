//
// Created by DiaLight on 20.07.2024.
//

#ifndef FLAME_USE_WHEEL_TO_ZOOM_H
#define FLAME_USE_WHEEL_TO_ZOOM_H

#include <Windows.h>

typedef struct DIDEVICEOBJECTDATA DIDEVICEOBJECTDATA;

namespace patch::use_wheel_to_zoom {

    extern bool enabled;
    void window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
    void dinput_proc(DIDEVICEOBJECTDATA *data);

}


#endif //FLAME_USE_WHEEL_TO_ZOOM_H
