//
// Created by DiaLight on 7/6/2026.
//

#ifndef FLAME_MAT_H
#define FLAME_MAT_H

#include "dk2/utils/Mat3x3f.h"

namespace dk2 {

    inline Mat3x3f transpose(const Mat3x3f &lhs) {
            return Mat3x3f {.m={
                    {lhs.m[0][0], lhs.m[1][0], lhs.m[2][0]},
                    {lhs.m[0][1], lhs.m[1][1], lhs.m[2][1]},
                    {lhs.m[0][2], lhs.m[1][2], lhs.m[2][2]},
            }};
    }

    inline Mat3x3f operator *(const Mat3x3f &lhs, const Mat3x3f &rhs) {
        return Mat3x3f {.m={
                {
                        lhs.m[0][0] * rhs.m[0][0] + lhs.m[0][1] * rhs.m[1][0] + lhs.m[0][2] * rhs.m[2][0],
                        lhs.m[0][0] * rhs.m[0][1] + lhs.m[0][1] * rhs.m[1][1] + lhs.m[0][2] * rhs.m[2][1],
                        lhs.m[0][0] * rhs.m[0][2] + lhs.m[0][1] * rhs.m[1][2] + lhs.m[0][2] * rhs.m[2][2],
                },
                {
                        lhs.m[1][0] * rhs.m[0][0] + lhs.m[1][1] * rhs.m[1][0] + lhs.m[1][2] * rhs.m[2][0],
                        lhs.m[1][0] * rhs.m[0][1] + lhs.m[1][1] * rhs.m[1][1] + lhs.m[1][2] * rhs.m[2][1],
                        lhs.m[1][0] * rhs.m[0][2] + lhs.m[1][1] * rhs.m[1][2] + lhs.m[1][2] * rhs.m[2][2],
                },
                {
                        lhs.m[2][0] * rhs.m[0][0] + lhs.m[2][1] * rhs.m[1][0] + lhs.m[2][2] * rhs.m[2][0],
                        lhs.m[2][0] * rhs.m[0][1] + lhs.m[2][1] * rhs.m[1][1] + lhs.m[2][2] * rhs.m[2][1],
                        lhs.m[2][0] * rhs.m[0][2] + lhs.m[2][1] * rhs.m[1][2] + lhs.m[2][2] * rhs.m[2][2],
                },
        }};
    }

}

#endif //FLAME_MAT_H
