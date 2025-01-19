//
// Created by DiaLight on 10.10.2024.
//
#include "dk2/CCamera.h"
#include "patches/micro_patches.h"


void dk2::CCamera::zoomRel_449CA0(int delta) {
    if ((this->fD92 & 8) != 0 || this->endTime) return;
    int min = this->minZoomLevel;
    int max = this->maxZoomLevel - 1;
    if(patch::increase_zoom_level::enabled) {
        max += 50000;
        if(min > 2000) min -= 2000;
    }
    int newCur = delta + this->curZoomLevel;
    this->curZoomLevel = newCur;
    if (newCur <= min)
        newCur = min;
    if (newCur >= max) {
        newCur = max;
    } else if (newCur <= min) {
        newCur = min;
    }
    this->curZoomLevel = newCur;
}
