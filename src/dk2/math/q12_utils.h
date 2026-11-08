//
// Created by DiaLight on 5/17/2025.
//

#ifndef INT_FLOAT_H
#define INT_FLOAT_H

#include "dk2/utils/Q12.h"
#include "dk2/utils/Vec3q12.h"



namespace dk2 {

    // uint32_t as float with fixed 12 bit precision
    inline Q12 Q12_encode(float value) { return Q12 { (uint32_t) (value * 4096.f) }; }
    inline float Q12_decode(const Q12 &fl) { return (float) (int32_t) fl.value / 4096.f; }

    inline Q12 operator +(const Q12 &lhs, const Q12 &rhs) {
        return Q12 {.value = rhs.value + lhs.value};
    }

    inline Q12 operator -(const Q12 &lhs, const Q12 &rhs) {
        return Q12 {.value = rhs.value - lhs.value};
    }

    inline Q12 operator *(const Q12 &lhs, const Q12 &rhs) {
        return Q12 {.value = (uint32_t) (
                (int64_t) (
                        (int)rhs.value * (int64_t)(int)lhs.value
                ) >> 12
        )};
    }

    inline Q12 operator /(const Q12 &lhs, const Q12 &rhs) {
        return Q12 {.value = (uint32_t) (
                (int64_t) ((uint64_t) lhs.value << 12) / (int) rhs.value
        )};
    }


    inline Vec3f Q12_decode(const Vec3q12 &fl) {
        return Vec3f {
                Q12_decode(fl.x),
                Q12_decode(fl.y),
                Q12_decode(fl.z),
        };
    }
    inline Vec3q12 Q12_encode(float x, float y, float z) {
        return Vec3q12 {
                Q12_encode(x),
                Q12_encode(y),
                Q12_encode(z),
        };
    }
    inline Vec3q12 Q12_encode(Vec3f v) {
        return Vec3q12 {
                Q12_encode(v.x),
                Q12_encode(v.y),
                Q12_encode(v.z),
        };
    }

    static Vec3q12 operator +(const Vec3q12 &lhs, const Vec3q12 &rhs) {
        return Vec3q12 {
                .x=lhs.x + rhs.x,
                .y=lhs.y + rhs.y,
                .z=lhs.z + rhs.z,
        };
    }

    static Vec3q12 operator -(const Vec3q12 &lhs, const Vec3q12 &rhs) {
        return Vec3q12 {
                .x=lhs.x - rhs.x,
                .y=lhs.y - rhs.y,
                .z=lhs.z - rhs.z,
        };
    }

    static Vec3q12 operator *(const Vec3q12 &lhs, const Vec3q12 &rhs) {
        return Vec3q12 {
                .x=lhs.x * rhs.x,
                .y=lhs.y * rhs.y,
                .z=lhs.z * rhs.z,
        };
    }

    static Vec3q12 operator /(const Vec3q12 &lhs, const Vec3q12 &rhs) {
        return Vec3q12 {
                .x=lhs.x / rhs.x,
                .y=lhs.y / rhs.y,
                .z=lhs.z / rhs.z,
        };
    }

}



#endif //INT_FLOAT_H
