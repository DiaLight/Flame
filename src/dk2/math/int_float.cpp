//
// Created by DiaLight on 5/17/2025.
//

#include "int_float.h"


dk2::IntFloat12 dk2ex::IFl12_from(uint32_t value) {
    return dk2::IntFloat12 { value << 12 };
}
dk2::IntFloat12 dk2ex::IFl12_from(float value) {
    return dk2::IntFloat12 { (uint32_t) (value * 4096.0) };
}
float dk2ex::toFloat(dk2::IntFloat12 &fl) {
    return fl.value / 4096.0;
}
