//
// Created by DiaLight on 10.10.2024.
//
#include "dk2/CCamera.h"
#include "patches/micro_patches.h"
#include "dk2/math/q12_utils.h"


void dk2::CCamera::zoomRel_449CA0(Q12 delta) {
    if ((this->fD92 & 8) != 0 || this->endTime) return;
    Q12 min {.value = this->minZoomLevel };
    Q12 max {.value = this->maxZoomLevel - 1 };
    if(patch::increase_zoom_level::enabled) {
        max.value += 50000;
        if(min.value > 2000) min.value -= 2000;
    }
    Q12 newCur = delta + this->curZoomLevel;
    this->curZoomLevel = newCur;
    if (newCur.value <= min.value)
        newCur = min;
    if (newCur.value >= max.value) {
        newCur = max;
    } else if (newCur.value <= min.value) {
        newCur = min;
    }
    this->curZoomLevel = newCur;
}
