//
// Created by DiaLight on 8/4/2026.
//

#ifndef FLAME_IMGUI_VISUAL_DEBUG_H
#define FLAME_IMGUI_VISUAL_DEBUG_H

#include "imgui.h"

namespace patch::opengl_patch {
    void imgui_tick();
}

inline ImVec2 operator +(const ImVec2 &lhs, const ImVec2 &rhs) {
    return ImVec2 {
        lhs.x + rhs.x,
        lhs.y + rhs.y,
    };
}
inline ImVec2 operator -(const ImVec2 &lhs, const ImVec2 &rhs) {
    return ImVec2 {
        lhs.x - rhs.x,
        lhs.y - rhs.y,
    };
}
inline ImVec2 operator *(const ImVec2 &lhs, float value) {
    return ImVec2 {
            lhs.x * value,
            lhs.y * value,
    };
}
inline ImVec2 operator /(const ImVec2 &lhs, float value) {
    return ImVec2 {
            lhs.x / value,
            lhs.y / value,
    };
}

#endif //FLAME_IMGUI_VISUAL_DEBUG_H
