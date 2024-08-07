//
// Created by DiaLight on 20.07.2024.
//

#ifndef FLAME_REPLACE_MOUSE_DINPUT_TO_USER32_H
#define FLAME_REPLACE_MOUSE_DINPUT_TO_USER32_H

#include <Windows.h>

namespace replace_mouse_dinput_to_user32 {

    extern bool enabled;
    void emulate_dinput_from_user32(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
    void handle_mouse_move(HWND hWnd, POINT pos);
    void release_handled_dinput_actions();

}


#endif //FLAME_REPLACE_MOUSE_DINPUT_TO_USER32_H
