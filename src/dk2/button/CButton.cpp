//
// Created by DiaLight on 7/12/2026.
//
#include "dk2/button/CButton.h"
#include "dk2/utils/AABB.h"
#include "dk2/gui/CWindow.h"

dk2::AABB *dk2::CButton::getScreenAABB(AABB *out) {

    AABB winPos;
    this->f51_pWindow->getScreenPos(&winPos);

    int thisRight = this->pos.x + this->pos.w;
    int thisBottom = this->pos.y + this->pos.h;

    int minX;
    int maxX;
    if ((this->f61_posFlags & 2) != 0) {
        minX = winPos.maxX - thisRight;
        maxX = winPos.maxX - this->pos.x;
    } else {
        minX = winPos.minX + this->pos.x;
        maxX = winPos.minX + thisRight;
    }

    int minY;
    int maxY;
    if ((this->f61_posFlags & 4) != 0) {
        minY = winPos.maxY - thisBottom;
        maxY = winPos.maxY - this->pos.y;
    } else {
        minY = winPos.minY + this->pos.y;
        maxY = winPos.minY + thisBottom;
    }
    *out = AABB {minX, minY, maxX, maxY};
    return out;
}
