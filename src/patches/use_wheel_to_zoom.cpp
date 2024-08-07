//
// Created by DiaLight on 20.07.2024.
//

#include "use_wheel_to_zoom.h"
#include "dk2_globals.h"
#include <windowsx.h>

bool use_wheel_to_zoom::enabled = true;
void use_wheel_to_zoom::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch (Msg) {
        case WM_MOUSEWHEEL: {
            DWORD fwKeys = GET_KEYSTATE_WPARAM(wParam);
            DWORD zDelta = GET_WHEEL_DELTA_WPARAM(wParam);  // +-120*speed
            DWORD xPos = GET_X_LPARAM(lParam);
            DWORD yPos = GET_Y_LPARAM(lParam);
//            printf("k=%08X d=%d {%d %d}\n", fwKeys, zDelta, xPos, yPos);
            dk2::CBridge_instance.camera.zoomRel_449CA0(-zDelta * 50);
            break;
        }
    }
}

namespace {
    DWORD g_lastTimestamp = 0;
}
void use_wheel_to_zoom::dinput_proc(DIDEVICEOBJECTDATA *data) {
    switch (data->dwOfs) {
        case DIMOFS_Z: {  // mouse wheel
            int zDelta = data->dwData;  // +-150 with timestamp
            int tsDelta = data->dwTimeStamp - g_lastTimestamp;
            g_lastTimestamp = data->dwTimeStamp;
//            printf("wheel: %d, ts: %d\n", data->dwData, tsDelta);
            int mult = 80;
            if (tsDelta > 100) mult = 40;
            if (tsDelta > 500) mult = 20;
            dk2::CBridge_instance.camera.zoomRel_449CA0(-zDelta * mult);
            break;
        }
    }
}
