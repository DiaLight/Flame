//
// Created by DiaLight on 11/8/2025.
//

#ifndef FLAME_WELCOME_WINDOW_IMGUI_H
#define FLAME_WELCOME_WINDOW_IMGUI_H

#include "welcome_window.h"
#include "imgui.h"
#include <Windows.h>

namespace patch::welcome_window {

    void *create(ImGuiIO& io, ImVec4 &clear_color, bool &done, welcome_data_t& data);
    void tick(void *ptr);
    void destroy(void *ptr);

    ImTextureID LoadTextureFromBuffer(void* data, size_t size, SIZE& texSize);

}

#endif // FLAME_WELCOME_WINDOW_IMGUI_H
