//
// Created by DiaLight on 7/11/2026.
//

#ifndef FLAME_COLOR_H
#define FLAME_COLOR_H

#include "dk2/utils/Color3f.h"

namespace dk2 {

    inline Color3f operator+(const Color3f &lhs, const Color3f &rhs) {
        return Color3f{
                .r=lhs.r + rhs.r,
                .g=lhs.g + rhs.g,
                .b=lhs.b + rhs.b,
        };
    }

    inline Color3f operator *(const Color3f &lhs, float rhs) {
        return Color3f {
                .r=lhs.r * rhs,
                .g=lhs.g * rhs,
                .b=lhs.b * rhs,
        };
    }

    inline Color3f operator /(const Color3f &lhs, float rhs) {
        return Color3f {
                .r=lhs.r / rhs,
                .g=lhs.g / rhs,
                .b=lhs.b / rhs,
        };
    }

}

#endif //FLAME_COLOR_H
