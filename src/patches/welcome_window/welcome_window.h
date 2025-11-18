//
// Created by DiaLight on 10/12/2025.
//

#ifndef FLAME_WELCOME_WINDOW_H
#define FLAME_WELCOME_WINDOW_H

#include <Windows.h>
#include <vector>

namespace patch::welcome_window {

    struct DisplayMode_t {
        size_t width;
        size_t height;
    };

    struct welcome_data_t {
        bool play = false;
        const wchar_t *win32_class_name;
        const wchar_t *win32_title;
        SIZE win32_size;
        std::vector<DisplayMode_t> modes;
    };

    bool imgui_main(welcome_data_t& data);
    
}

#endif // FLAME_WELCOME_WINDOW_H
