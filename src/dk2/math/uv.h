//
// Created by DiaLight on 8/5/2026.
//

#ifndef FLAME_UV_H
#define FLAME_UV_H

#include <cmath>
#include "dk2/utils/Uv2f.h"

namespace dk2 {

    inline Uv2f operator +(const Uv2f &lhs, float rhs) {
        return Uv2f {
                .u=lhs.u + rhs,
                .v=lhs.v + rhs,
        };
    }

    inline Uv2f operator +(const Uv2f &lhs, const Uv2f &rhs) {
        return Uv2f {
                .u=lhs.u + rhs.u,
                .v=lhs.v + rhs.v,
        };
    }

    inline Uv2f operator -(const Uv2f &lhs, const Uv2f &rhs) {
        return Uv2f {
                .u=lhs.u - rhs.u,
                .v=lhs.v - rhs.v,
        };
    }

    inline Uv2f operator -(const Uv2f &lhs, float rhs) {
        return Uv2f {
                .u=lhs.u - rhs,
                .v=lhs.v - rhs,
        };
    }

    inline Uv2f operator -(const Uv2f &vec) {
        return Uv2f {
                .u=-vec.u,
                .v=-vec.v,
        };
    }

    inline Uv2f operator *(const Uv2f &lhs, const Uv2f &rhs) {
        return Uv2f {
                .u=lhs.u * rhs.u,
                .v=lhs.v * rhs.v,
        };
    }

    inline Uv2f operator *(const Uv2f &lhs, float rhs) {
        return Uv2f {
                .u=lhs.u * rhs,
                .v=lhs.v * rhs,
        };
    }

    inline Uv2f operator /(const Uv2f &lhs, const Uv2f &rhs) {
        return Uv2f {
                .u=lhs.u * rhs.u,
                .v=lhs.v * rhs.v,
        };
    }

    inline Uv2f operator /(const Uv2f &lhs, float rhs) {
        return Uv2f {
                .u=lhs.u / rhs,
                .v=lhs.v / rhs,
        };
    }
    
}

#endif //FLAME_UV_H
