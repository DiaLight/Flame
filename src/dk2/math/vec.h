//
// Created by DiaLight on 7/3/2026.
//

#ifndef FLAME_VEC_H
#define FLAME_VEC_H

#include <cmath>
#include "dk2/utils/Vec3i.h"
#include "dk2/utils/Vec3f.h"
#include "dk2/utils/Mat3x3f.h"

namespace dk2 {

    inline Vec3i operator +(const Vec3i &lhs, const Vec3i &rhs) {
        return Vec3i {
            .x=lhs.x + rhs.x,
            .y=lhs.y + rhs.y,
            .z=lhs.z + rhs.z,
        };
    }

    inline Vec3f operator +(const Vec3f &lhs, const Vec3f &rhs) {
        return Vec3f {
            .x=lhs.x + rhs.x,
            .y=lhs.y + rhs.y,
            .z=lhs.z + rhs.z,
        };
    }

    inline Vec3f operator -(const Vec3f &lhs, const Vec3f &rhs) {
        return Vec3f {
            .x=lhs.x - rhs.x,
            .y=lhs.y - rhs.y,
            .z=lhs.z - rhs.z,
        };
    }

    inline Vec3f operator -(const Vec3f &vec) {
        return Vec3f {
            .x=-vec.x,
            .y=-vec.y,
            .z=-vec.z,
        };
    }

    inline Vec3f operator *(const Vec3f &lhs, const Vec3f &rhs) {
        return Vec3f {
            .x=lhs.x * rhs.x,
            .y=lhs.y * rhs.y,
            .z=lhs.z * rhs.z,
        };
    }

    inline Vec3f operator *(const Vec3f &lhs, float rhs) {
        return Vec3f {
            .x=lhs.x * rhs,
            .y=lhs.y * rhs,
            .z=lhs.z * rhs,
        };
    }

    inline Vec3f operator /(const Vec3f &lhs, const Vec3f &rhs) {
        return Vec3f {
            .x=lhs.x * rhs.x,
            .y=lhs.y * rhs.y,
            .z=lhs.z * rhs.z,
        };
    }

    inline Vec3f operator /(const Vec3f &lhs, float rhs) {
        return Vec3f {
                .x=lhs.x / rhs,
                .y=lhs.y / rhs,
                .z=lhs.z / rhs,
        };
    }

    inline Vec3f operator *(const Mat3x3f &lhs, const Vec3f &inVec) {
        return Vec3f {
            .x=lhs.m[0][0] * inVec.x + lhs.m[1][0] * inVec.y + lhs.m[2][0] * inVec.z,
            .y=lhs.m[0][1] * inVec.x + lhs.m[1][1] * inVec.y + lhs.m[2][1] * inVec.z,
            .z=lhs.m[0][2] * inVec.x + lhs.m[1][2] * inVec.y + lhs.m[2][2] * inVec.z,
        };
    }

    inline Vec3f norm(const Vec3f &lhs) {
        return lhs * (1.0 / sqrt(
                lhs.x * lhs.x +
                lhs.y * lhs.y +
                lhs.z * lhs.z
        ));
    }


}


namespace dk2 {

    inline int32_t strangeOptimizedMultiplyAddCast(float v, float m, float a) {
        int32_t value;
//        {  // why??? what exactly is here optimized? if following code is equivalent to v * m + a?
//            float v12 = 12582912.0 - (0.49998999 - (v * m + a));
//            value = ((*(uint32_t *) &v12) & 0x7FFFFF) - 0x400000;
//        }
        value = (int32_t) (v * m + a);
        return value;
    }

}

#endif //FLAME_VEC_H
