//
// Created by DiaLight on 6/22/2026.
//

#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/opengl/opengl_patch.h"
#include "tools/visual_debug.h"
#include "dk2/InputCursor.h"
#include "dk2/inputs/InputSurf.h"
#include "dk2/MyCb6723D0.h"

namespace dk2 {

    StubStruc68F650 g_interfaceCursorArr[16] {
            {0,                         1, 0, 0, 0, 0, 1, simpleCursor_40E3C0, 0, 0, 0, 0, 0},
            {"Point.png",               0x29, 0x52, 0x35, 2, 0x11, 0x1E, simpleCursor_40E3C0, 0, 0, 0, 0, 0},
            {"SmallPoint.png",          1, 0x2A, 0x14, 2, 2, 1, simpleCursor_40E3C0, 0, 0, 0, 0, 0},
            {"Idle.png",                1, 0x53, 0x27, 2, 4, 0x1E, simpleCursor_40E3C0, 0, 0, 0, 0, 0},
            {"PickAxeHold.png",         1, 0x54, 0x56, 4, 0x33, 1, simpleCursor_40E3C0, 0, 0, 0, 0, 0},
            {"PickAxeTag.png",          1, 0x58, 0x41, 7, 0x1E, 0x1E, pickAxeCursor_40E300, 0, 0, 0, 0, 0},
            {"PickAxeHoldTagging.png",  1, 0x58, 0x41, 7, 0x1E, 1, simpleCursor_40E3C0, 0, 0, 0, 0, 0},
            {"HoldThing.png",           1, 0x4A, 0x46, 8, 0x2A, 0x0F, cursor2_40E3F0, 0, 0, 0, 0, 0},
            {"DropThing.png",           0x0E, 0x58, 0x67, 2, 0x40, 0x1E, cursor2_40E3F0, 0, 0, 0, 0, 0},
            {"HoldGold.png",            1, 0x3F, 0x2B, (int) 0xFFFFFFEE, 7, 0x0F,cursor2_40E3F0, 0, 0, 0, 0, 0},
            {"DropGold.png",            0x10, 0x57, 0x5F, 5, 0x3B, 0x1E, cursor2_40E3F0, 0, 0, 0, 0, 0},
            {"Slap.png",                0x0F, 0x7E, 0x63, 2, 0x40, 0x1E, slapCursor_40E520, 0, 0, 0, 0, 0},
            {"Idle.png",                1, 0x53, 0x27, 2, 4, 0x1E, simpleCursor_40E3C0, 0, 0, 0, 0, 0},
            {"SpellCast.png",           0x0C, 0x57, 0x68, 1, 0x41, 0x1E, spellcastCursor_40E5E0, 0, 0, 0, 0, 0},
            {"SpellPossess.png",        6, 0x40, 0x40, 0x20, 0x20, 0x0F, simpleCursor_40E3C0, 0, 0, 0, 0, 0},
            {"SpellPossessNoGo.png",    1, 0x40, 0x40, 0x20, 0x20, 1, simpleCursor_40E3C0, 0, 0, 0, 0, 0},
    };
}



int *dk2::CursorDrawer::resetCursorSize(int *pstatus) {
    this->cursorSize.x = 0;
    this->cursorSize.y = 0;
    return *pstatus = 0, pstatus;
}

int *dk2::CursorDrawer::setCursorImage(
        int *pstatus,
        MyDdSurfaceEx *newCursor,
        AABB *newCursorAabb,
        Pos2i *cursorToMouseOffs) {
    int status;
    if (!newCursor) {
        this->resetCursorSize(pstatus);
        return pstatus;
    }
    // if do expand cursor surf
    if ((unsigned int) (newCursorAabb->maxX - newCursorAabb->minX) > this->cursorSurfSize.x
        || (unsigned int) (newCursorAabb->maxY - newCursorAabb->minY) > this->cursorSurfSize.y) {
        if (this->isCursorsCreated) {
            if (this->prevIdx) {
                Pos2i cursorPos;
                cursorPos.x = this->cursorAabbScreenCut[0].minX;
                cursorPos.y = this->cursorAabbScreenCut[0].minY;
                this->updateCursorAndDraw(&cursorPos, 0);
            }
            this->releaseCursorSurfaces();
        }

        unsigned int tx = newCursorAabb->maxX - newCursorAabb->minX;
        if(tx >= this->cursorSurfSize.x) this->cursorSurfSize.x = (int) tx;

        unsigned int ty = newCursorAabb->maxY - newCursorAabb->minY;
        if(ty >= this->cursorSurfSize.y) this->cursorSurfSize.y = (int) ty;
    }
    if (!this->isCursorsCreated) {
        if (*this->recreateCursorSurfaces(&status) < 0) {
            return *pstatus = status, pstatus;
        }
    }
    // resize all ingameCursorFullSize to cursorSize
    AABB *p_aabb = &this->ingameCursorFullSize[0];
    for (int i = 0; i < 3; ++i) {
        p_aabb->move(0, 0);
        p_aabb->maxX = p_aabb->minX + this->cursorSize.x;
        p_aabb->maxY = p_aabb->minY + this->cursorSize.y;
        p_aabb++;
    }
    this->cursorSize.y = newCursorAabb->maxY - newCursorAabb->minY;
    this->cursorSize.x = newCursorAabb->maxX - newCursorAabb->minX;
    static_MyDdSurfaceEx_BltWait(
            &status,
            &this->cursorSurf[0].ddSurfEx,
            this->ingameCursorFullSize[0].minX,
            this->ingameCursorFullSize[0].minY,
            newCursor,
            newCursorAabb,
            0);
    if (status < 0) return *pstatus = status, pstatus;
    this->mouseToCursorOffs.x = -cursorToMouseOffs->x;
    this->mouseToCursorOffs.y = -cursorToMouseOffs->y;
    this->doCursorRedraw = 1;
    return *pstatus = 0, pstatus;
}

int *dk2::InputCursor::setIconAndDraw(int *a2_pstatus, MyDdSurfaceEx *a3, AABB *a4, Pos2i *a5) {
    this->waitForSema(1);
    int status;
    this->cursorDrawer->setCursorImage(&status, a3, a4, a5);
    this->setAndRelease();
    this->drawCursor(getTimeMs());
    return *a2_pstatus = status, a2_pstatus;
}

int *dk2::MyInputManagerCb::setCursorIconAndDraw(int *pstatus, MyDdSurfaceEx *a3, AABB *a4, Pos2i *a5) {
    int status;
    this->resolveChildCb(&status);
    if (status < 0) return *pstatus = status, pstatus;
    this->pchildcb->inputCursor.setIconAndDraw(pstatus, a3, a4, a5);
    return pstatus;
}

int *__cdecl dk2::static_MyInputManagerCb_setCursorIconAndDraw(int *pstatus, MyDdSurfaceEx *a2, AABB *a3, Pos2i *a4) {
    MyInputManagerCb_instance.setCursorIconAndDraw(pstatus, a2, a3, a4);
    return pstatus;
}


dk2::AABB *dk2::InputSurfBase::getOffScreenAabb(AABB *out) {
    if(!patch::opengl_patch::enabled) {
        if (!ge_dk2dd_get(0)) {
            *out = {0, 0, 0, 0};
            return out;
        }
    }
    MyDdSurfaceEx *surf = this->v_getCurOffScreenSurf();
    MySurface *desc = surf->updateDesc();
    *out = {0, 0, desc->size.w, desc->size.h};
    return out;
}

int *dk2::InputCursor::initAndUpdateAabb(int *pstatus, Pos2i *mousePos) {
    this->waitForSema(true);
    this->cursorDrawer = CursorDrawer_getInstance();
    this->pMousePos = mousePos;
    AABB v7;
    this->cursorDrawer->screenAabb = *this->pInputSurf->v_getOffScreenAabb(&v7);
    this->setAndRelease();
    return *pstatus = 0, pstatus;
}

bool dk2::CursorDrawer::drawCursor() {
    if (this->prevIdx == 0) return true;
    int status;
    if (this->bpt_isCursorAabbIntersectsWithPrevPos) {
        static_MyDdSurfaceEx_BltWait(
                &status,
                &this->cursorSurf[this->prevIdx].ddSurfEx,
                this->bpt_cursorIntersection[this->prevIdx].minX,
                this->bpt_cursorIntersection[this->prevIdx].minY,
                &this->cursorSurf[0].ddSurfEx,
                &this->bpt_cursorIntersection[0],
                1);
    } else {
        static_MyDdSurfaceEx_BltWait(
                &status,
                this->pScreen[this->prevIdx],
                this->cursorAabbScreenCut[this->prevIdx].minX,
                this->cursorAabbScreenCut[this->prevIdx].minY,
                &this->cursorSurf[this->prevIdx].ddSurfEx,
                &this->cursorSizeAabb[this->prevIdx],
                0);
    }
    if (status < 0) return false;
    return true;
}

bool dk2::CursorDrawer::drawCursorToScreenSurf() {
    if (!this->pScreen[0]) return true;
    int status;
    static_MyDdSurfaceEx_BltWait(
            &status,
            this->pScreen[0],
            this->cursorAabbScreenCut[0].minX,
            this->cursorAabbScreenCut[0].minY,
            &this->cursorSurf[0].ddSurfEx,
            this->cursorSizeAabb,
            1);
    if (status < 0) return false;
    return true;
}

void dk2::CursorDrawer::calcCursorAabbFromMouse(Pos2i *mousePos) {
    this->mousePos = *mousePos;
    Pos2i cursor {
            mousePos->x + this->mouseToCursorOffs.x,
            mousePos->y + this->mouseToCursorOffs.y,
    };

    AABB cursorAabb {
        cursor.x, cursor.y,
        cursor.x + this->cursorSize.x,
        cursor.y + this->cursorSize.y,
    };

    AABB tmp;
    this->cursorAabbScreenCut[0] = *cursorAabb.intersection(&tmp, &this->screenAabb);

    this->cursorSizeAabb[0].minX = this->cursorAabbScreenCut[0].minX - cursor.x;
    this->cursorSizeAabb[0].minY = this->cursorAabbScreenCut[0].minY - cursor.y;
    this->cursorSizeAabb[0].maxX = this->cursorAabbScreenCut[0].maxX - cursor.x;
    this->cursorSizeAabb[0].maxY = this->cursorAabbScreenCut[0].maxY - cursor.y;

    if (!this->pScreen[0]) this->idx = 0;

    if (
            this->cursorAabbScreenCut[0].minX > this->cursorAabbScreenCut[0].maxX ||
            this->cursorAabbScreenCut[0].minY > this->cursorAabbScreenCut[0].maxY ||
            this->cursorAabbScreenCut[0].minX == this->cursorAabbScreenCut[0].maxX ||
            this->cursorAabbScreenCut[0].minY == this->cursorAabbScreenCut[0].maxY
    ) {
        this->idx = 0;
        this->pScreen[0] = NULL;
        this->bpt_isCursorAabbIntersectsWithPrevPos = 0;
        return;
    }

    int isCursorAabbIntersectsWithPrevPos = 0;
    if (this->idx) {
        if (this->prevIdx) {
            if (this->cursorAabbScreenCut->isIntersects(&this->cursorAabbScreenCut[this->prevIdx])) {
                isCursorAabbIntersectsWithPrevPos = 1;
            }
        }
    }
    this->bpt_isCursorAabbIntersectsWithPrevPos = isCursorAabbIntersectsWithPrevPos;
    if (!isCursorAabbIntersectsWithPrevPos) return;


    AABB inter;
    this->cursorAabbScreenCut->intersection(&inter, &this->cursorAabbScreenCut[this->prevIdx]);

    this->bpt_cursorIntersection[0].minX = inter.minX - cursor.x;
    this->bpt_cursorIntersection[0].minY = inter.minY - cursor.y;
    this->bpt_cursorIntersection[0].maxX = inter.maxX - cursor.x;
    this->bpt_cursorIntersection[0].maxY = inter.maxY - cursor.y;

    Pos2i v1 {
            this->ingameCursorFullSize[this->idx].minX,
            this->ingameCursorFullSize[this->idx].minY,
    };

    this->bpt_cursorIntersection[this->idx] = AABB {
            this->bpt_cursorIntersection[0].minX + v1.x,
            this->bpt_cursorIntersection[0].minY + v1.y,
            this->bpt_cursorIntersection[0].maxX + v1.x,
            this->bpt_cursorIntersection[0].maxY + v1.y,
    };

    Pos2i v2 {
            this->cursorSizeAabb[this->prevIdx].minX,
            this->cursorSizeAabb[this->prevIdx].minY,
    };
    Pos2i v3 {
            this->cursorAabbScreenCut[this->prevIdx].minX,
            this->cursorAabbScreenCut[this->prevIdx].minY,
    };
    this->bpt_cursorIntersection[this->prevIdx] = AABB {
            inter.minX + v2.x - v3.x,
            inter.minY + v2.y - v3.y,
            inter.maxX + v2.x - v3.x,
            inter.maxY + v2.y - v3.y,
    };
}

void dk2::CursorDrawer::updateCursorAndDraw(Pos2i *cursorPos, MyDdSurfaceEx *screenDds) {
    this->pScreen[0] = screenDds;
    if (!this->isCursorsCreated) return;
    if (this->prevIdx) {
        bool mouseMoved = cursorPos->x != this->mousePos.x || cursorPos->y != this->mousePos.y;
        if (!mouseMoved && !this->doCursorRedraw) return;
    }
    this->doCursorRedraw = 0;
    this->calcCursorAabbFromMouse(cursorPos);
    // every second frame try to draw old cursor instead of full redraw
    if (!this->drawBgAndIntersectionToCursorSurf()) return;

    // full cursor redraw
    this->drawCursor();
    this->drawCursorToScreenSurf();
    this->nextFrame();
}

void dk2::InputCursor::drawCursor(int timestamp) {
    if (!this->cursorDrawer) return;
    if (this->aBool) return;
    if (timestamp - this->timestamp <= 0) return;
    MyDdSurfaceEx *surface = this->pInputSurf->v_getPrimarySurf();
    if (!surface) return;
    if (!this->waitForSema(0)) return;
    this->cursorDrawer->updateCursorAndDraw(this->pMousePos, surface);
    this->timestamp = timestamp + this->timestampDelta;
    this->setAndRelease();
}

void dk2::CursorDrawer::updateCursorAndForceDraw(
        Pos2i *mousePos, MyDdSurface *surf1, MyDdSurfaceEx *surf2,
        char a5, char a6) {
    if (a5 && a6) {
        this->bpt_forceDraw = this->prevIdx;
    }
    this->prevIdx = 0;
    this->updateCursorAndDraw(mousePos, surf2);
}

void dk2::InputCursor::Event1_2Handler_updateCursor() {
    this->waitForSema(1);
    InputSurf *f4_pobj = this->pInputSurf;
    char forceDraw = (char)f4_pobj->v_isSurfaceFlag();
    char f12__doDrawCursor = this->_doDrawCursor;
    MyDdSurfaceEx *offscr = f4_pobj->v_getCurOffScreenSurf();
    MyDdSurfaceEx *primary = f4_pobj->v_getPrimarySurf();
    this->cursorDrawer->updateCursorAndForceDraw(this->pMousePos, &primary->dd_surf, offscr, f12__doDrawCursor, forceDraw);
}

void dk2::CursorDrawer::nextFrame() {
    this->prevIdx = this->idx;
    if (this->idx == 0) {
        if(this->bpt_forceDraw != 2) {
            this->idx = 2;
        } else {
            this->idx = 1;
        }
        return;
    }
    if (this->idx == 1) {
        this->idx = 2;
        return;
    }
    if (this->idx == 2) {
        this->idx = 1;
        return;
    }
}

