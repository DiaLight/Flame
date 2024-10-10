//
// Created by DiaLight on 20.07.2024.
//

#ifndef FLAME_MICRO_PATCHES_H
#define FLAME_MICRO_PATCHES_H

#include <Windows.h>
#include <cstdint>

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

namespace force_32bit_everything {
    extern bool enabled;
}

namespace disable_bonus_damage {
    extern bool enabled;
}

namespace backstab_fix {
    extern bool enabled;
}

namespace workshop_manufacture_build_time_fix {
    extern bool enabled;
}

namespace response_to_threat_fix {
    extern bool enabled;
}

namespace print_game_start_errors {
    extern bool enabled;
}

namespace creatures_setup_lair_fix {
    extern bool enabled;
}

namespace wooden_bridge_burn_fix {
    extern bool enabled;
}

namespace max_host_port_number_fix {
    extern bool enabled;
}

namespace increase_zoom_level {
    extern bool enabled;
}

namespace override_max_room_count {
    extern bool enabled;
    extern uint8_t limit;
}

namespace use_wasd_by_default_patch {
    extern bool enabled;
    void useAlternativeName(LPCSTR &lpValueName);
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

namespace remember_window_location_and_size {
    void setInitialSize(int x, int y);
    bool window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
    void patchWinLoc(int &xPos, int &yPos);
    void resizeWindow(HWND hWnd);
}

namespace skippable_title_screen {
    extern bool enabled;
    extern uint32_t waiting_time;
    bool skipKeyPressed();
}

namespace limit_fps {
    void call();
}


#endif //FLAME_MICRO_PATCHES_H
