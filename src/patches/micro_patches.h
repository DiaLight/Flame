//
// Created by DiaLight on 20.07.2024.
//

#ifndef FLAME_MICRO_PATCHES_H
#define FLAME_MICRO_PATCHES_H

#include <Windows.h>

namespace add_win10_support {
    extern bool enabled;
}

namespace use_cwd_as_dk2_home_dir {
    extern bool enabled;
}

namespace notify_another_instance_is_running {
    extern bool enabled;
}

namespace control_windowed_mode {
    extern bool enabled;
}

namespace fix_mouse_pos_on_resized_window {
    void window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
}

namespace fix_keyboard_state_on_alt_tab {
    void window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
}

namespace bring_to_foreground {
    void window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
}

namespace fix_close_window {
    void window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
}

namespace hide_mouse_cursor_in_window {
    bool window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
}

namespace skippable_title_screen {
    extern bool enabled;
    bool skipKeyPressed();
}


#endif //FLAME_MICRO_PATCHES_H
