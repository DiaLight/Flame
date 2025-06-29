//
// Created by DiaLight on 5/29/2025.
//
#include <dk2_functions.h>
#include <dk2_globals.h>
#include <dk2/button/button_types.h>
#include <dk2/button/CButton.h>
#include <dk2/gui/RenderButtonTextInfo.h>

#include "visual_debug.h"


namespace dk2 {
    void calcBounds(
        int alignTy, AABB &btnPos, uint32_t x16Idx, uint16_t btnIdx, CFrontEndComponent *frontend, AABB &scaledBounds
    ) {
        auto &textSurf = frontend->surf64_x16x30x6[x16Idx][btnIdx][4]; // regular text
        if (alignTy == 0) { // center by y
            scaledBounds.minX = textSurf.dwWidth;
            int scalefHeight = scaledBounds.maxY - scaledBounds.minY;
            int heightLeft = scalefHeight - textSurf.dwHeight;
            if (heightLeft > 0) {
                btnPos.minY = (heightLeft >> 1) + scaledBounds.minY;
            } else {
                btnPos.minY -= ((heightLeft >> 31) ^ heightLeft) / 2;
            }
            return;
        }
        if (alignTy == 1) { // center by y
            scaledBounds.minY = textSurf.dwHeight;
            int v18 = (scaledBounds.maxX - btnPos.minX) - textSurf.dwWidth;
            if (v18 > 0)
                btnPos.minX += v18;

            scaledBounds.minX = textSurf.dwWidth;
            int v16 = (scaledBounds.maxY - btnPos.minY) - textSurf.dwHeight;
            if (v16 > 0) {
                btnPos.minY += v16 >> 1;
            } else {
                btnPos.minY -= ((v16 >> 31) ^ v16) / 2;
            }
            return;
        }
        if (alignTy == 2) { // center by x and y
            scaledBounds.minY = textSurf.dwHeight;
            int v14 = (scaledBounds.maxX - btnPos.minX) - textSurf.dwWidth;
            if (v14 > 0) {
                btnPos.minX = (v14 >> 1) + btnPos.minX;
            } else {
                btnPos.minX = btnPos.minX - ((v14 >> 31) ^ v14) / 2;
            }

            scaledBounds.minX = textSurf.dwWidth;
            int v16 = (scaledBounds.maxY - btnPos.minY) - textSurf.dwHeight;
            if (v16 > 0) {
                btnPos.minY += v16 >> 1;
            } else {
                btnPos.minY -= ((v16 >> 31) ^ v16) / 2;
            }
        }
    }
}


char __cdecl dk2::CClickButton_render_532670(CButton *btn, CFrontEndComponent *front) {
    char result = g_initialized73E9D4;
    if (!g_initialized73E9D4) {
        g_initialized73E9D4 = 1;
        memset(d70D578_x30, 0, sizeof(d70D578_x30));
        memset(buttonHighlight_x30, 0, 30u);
        result = 0;
        memset(btnSoundLoaded_73E9A0_x30, 0, 30u);
    }
    CButton *v3 = btn;
    if (btn->f5D_isVisible != 1)
        return result;
    CFrontEndComponent *frontend = front;
    uint16_t btnIdx = LOWORD(btn->f30_arg);
    uint16_t alignTy = LOWORD(btn->f34_idxHigh);
    uint16_t x16Idx = HIWORD(btn->f34_idxHigh);
    front->arr_x16x30_hovered[x16Idx][btnIdx] = 0;
    AABB scaledBounds;
    AABB screenBounds = *v3->getScreenAABB(&scaledBounds);
    AABB *pScaledBounds = frontend->cgui_manager.scaleAabb_2560_1920(&scaledBounds, &screenBounds);
    AABB btnPos = *pScaledBounds;
    calcBounds(alignTy, btnPos, x16Idx, btnIdx, frontend, scaledBounds);

    // calc hover score
    if (btn->f45_containsCursor) {
        auto mousePos = frontend->cgui_manager.mousePos;
        auto aabb22 = frontend->aabb17_x16x30[x16Idx][btnIdx];
        if (mousePos.x >= aabb22.minX && mousePos.x < aabb22.maxX
            && mousePos.y >= aabb22.minY && mousePos.y < aabb22.maxY
        ) {
            if (!btnSoundLoaded_73E9A0_x30[btnIdx]) {
                MySound_ptr->v_fun_567810(0, frontend->f5AB9, 783);
                btnSoundLoaded_73E9A0_x30[btnIdx] = 1;
            }
            frontend->arr_x16x30_hovered[x16Idx][btnIdx] = 1;
            buttonHighlight_x30[btnIdx] = 8;
        }
    }

    // render hover glowing
    char highlightLevel = buttonHighlight_x30[btnIdx] - 1;
    buttonHighlight_x30[btnIdx] = highlightLevel;
    if (highlightLevel > 0) {
        int layer;
        if (highlightLevel <= 4)
            layer = highlightLevel - 1;
        else
            layer = 3;
        // Render glowing
        int status;
        MySurface_static_copy(
            &status,
            &frontend->surf65_btnRenderOut,
            btnPos.minX,
            btnPos.minY,
            &frontend->surf64_x16x30x6[x16Idx][btnIdx][layer],
            NULL,
            0);
    }
    int layer2 = 4;
    if (frontend->arr_x16x30_hovered[x16Idx][btnIdx] == 1)
        layer2 = 5;
    // Render text
    int status;
    MySurface_static_copy(
        &status,
        &frontend->surf65_btnRenderOut,
        btnPos.minX,
        btnPos.minY,
        &frontend->surf64_x16x30x6[x16Idx][btnIdx][layer2],
        NULL,
        0);

    highlightLevel = buttonHighlight_x30[btnIdx];
    if (highlightLevel < 0) {
        btnSoundLoaded_73E9A0_x30[btnIdx] = 0;
        buttonHighlight_x30[btnIdx] = -1;
    }
    return highlightLevel;
}

char dk2::CFrontEndComponent::renderButtonsText_5329A0(
    int a2_bufElementsCount,
    unsigned __int8 a3_x16Idx,
    RenderButtonTextInfo *a4_curBtnInfo,
    int a5_font
) {
    int status;
    Size2i v93_sizes[30];
    unsigned __int8 *v94_mbStringArr[30];
    int v96_rendererTyArr[30];
    AABB v96_aabs[30];
    uint8_t v91_localTextRenderer_buf[sizeof(MyTextRenderer)];
    MyTextRenderer &v91_localTextRenderer = *(MyTextRenderer*) v91_localTextRenderer_buf;

    v91_localTextRenderer.constructor();
    int *p_maxX = &v96_aabs[0].maxX;
    int v98_try_level = 0;
    int v7_left = 30;
    do {
        *(p_maxX - 2) = 0;
        *(p_maxX - 1) = 0;
        *p_maxX = 0;
        p_maxX[1] = 0;
        p_maxX += 4;
        --v7_left;
    } while (v7_left);
    Size2i *v8_pSize = v93_sizes;
    int v9_left = 30;
    do {
        v8_pSize->w = 0;
        v8_pSize->h = 0;
        ++v8_pSize;
        --v9_left;
    } while (v9_left);
    switch (a5_font) {
    case 1: g_FontObj1_instance.assign_constructor(&g_FontObj1_instance);
        break;
    case 2: g_FontObj1_instance.assign_constructor(&g_FontObj2_instance);
        break;
    case 3: g_FontObj1_instance.assign_constructor(&g_FontObj3_instance);
        break;
    case 4: g_FontObj1_instance.assign_constructor(&g_FontObj4_instance);
        break;
    case 5: g_FontObj1_instance.assign_constructor(&g_FontObj5_instance);
        break;
    case 6: g_FontObj1_instance.assign_constructor(&g_FontObj6_instance);
        break;
    case 7: g_FontObj1_instance.assign_constructor(&g_FontObj7_instance);
        break;
    case 8: g_FontObj1_instance.assign_constructor(&g_FontObj8_instance);
        break;
    case 9: g_FontObj1_instance.assign_constructor(&g_FontObj9_instance);
        break;
    default: break;
    }
    memset(v93_sizes, 0, sizeof(v93_sizes));
    CButton *f66_buttons = this->cgui_manager.findGameWindowById(a2_bufElementsCount)->f66_buttons;
    CButton *btnsCpy = f66_buttons;
    g_FontObj1_instance.reset_f10(&status);
    unsigned __int8 btnsCount;
    for (btnsCount = 0; f66_buttons; btnsCpy = f66_buttons) {
        auto *f24_renderFun = (char (__cdecl *)(CButton *, CFrontEndComponent *)) f66_buttons->f24_renderFun;
        if ((f24_renderFun == CClickButton_render_532670 || f24_renderFun == CButton_render_541F50)
            && f66_buttons->f6F_kind == 7
            && f66_buttons->f2C_textId) {
            unsigned __int8 *MbString = MyMbStringList_idx1091_getMbString(f66_buttons->f2C_textId);
            v94_mbStringArr[btnsCount] = MbString;
            AABB *v13_pAabb = &v96_aabs[btnsCount];
            AABB v77_aabb;
            *v13_pAabb = *f66_buttons->getScreenAABB(&v77_aabb);
            AABB v92_aabb;
            *v13_pAabb = *this->cgui_manager.scaleAabb_2560_1920(&v92_aabb, v13_pAabb);
            uint16_t alignTy = LOWORD(f66_buttons->f34_idxHigh);
            v96_rendererTyArr[btnsCount] = alignTy;
            switch (alignTy) {
            case 0: {
                v91_localTextRenderer.selectMyCR(&status, 0);
                v91_localTextRenderer.selectMyTR(&status, 2);
            }
            break;
            case 1: {
                v91_localTextRenderer.selectMyCR(&status, 1);
                v91_localTextRenderer.selectMyTR(&status, 2);
            }
            break;
            case 2: {
                v91_localTextRenderer.selectMyCR(&status, 2);
                v91_localTextRenderer.selectMyTR(&status, 2);
            }
            break;
            case 3: {
                v91_localTextRenderer.selectMyCR(&status, 3);
                v91_localTextRenderer.selectMyTR(&status, 3);
            }
            break;
            default: break;
            }
            AABB textAabb;
            memset(&textAabb, 0, sizeof(textAabb));
            v91_localTextRenderer.renderText2(
                &status,
                v13_pAabb,
                (char*) MbString,
                &g_FontObj1_instance,
                &textAabb);
            textAabb.minX -= 8;
            textAabb.minY -= 8;
            textAabb.maxX += 8;
            textAabb.maxY += 8;
            this->aabb17_x16x30[a3_x16Idx][btnsCount] = textAabb;
            int v21_width = 6 * (textAabb.maxX + 16) - 6 * textAabb.minX;
            f66_buttons = btnsCpy;
            int v20_btnIdx = btnsCount;
            v93_sizes[v20_btnIdx].w = v21_width;
            v93_sizes[v20_btnIdx].h = textAabb.maxY - textAabb.minY + 16;
            ++btnsCount;
        }
        f66_buttons = f66_buttons->f78_next;
    }
    RenderButtonTextInfo *v22_curBtnInfo = a4_curBtnInfo;
    if (a4_curBtnInfo && a4_curBtnInfo->btnId) {
        do {
            char **v23_pMbstr;
            char *v24_mbstr;
            if (v22_curBtnInfo->strId) {
                v23_pMbstr = (char**) &v94_mbStringArr[btnsCount];
                v24_mbstr = (char*) MyMbStringList_idx1091_getMbString(v22_curBtnInfo->strId);
            } else {
                v24_mbstr = v22_curBtnInfo->mbstr;
                v23_pMbstr = (char**) &v94_mbStringArr[btnsCount];
            }
            int f4_btnId = v22_curBtnInfo->btnId;
            *v23_pMbstr = v24_mbstr;

            CButton *v27_foundBtn = NULL;
            for (
                CButton *f78_next = this->cgui_manager.findGameWindowById(a2_bufElementsCount)->f66_buttons;
                f78_next != NULL;
                f78_next = f78_next->f78_next
            ) {
                if (f78_next->f70_id != f4_btnId) continue;
                v27_foundBtn = f78_next;
                break;
            }

            if (v27_foundBtn) {
                AABB screenAabb;
                *v27_foundBtn->getScreenAABB(&screenAabb);
                AABB scaledBtn;
                this->cgui_manager.scaleAabb_2560_1920(&scaledBtn, &screenAabb);
                v96_aabs[btnsCount] = scaledBtn;
                uint16_t alignTy = LOWORD(v27_foundBtn->f34_idxHigh);
                v96_rendererTyArr[btnsCount] = alignTy;
                switch (alignTy) {
                case 0: {
                    v91_localTextRenderer.selectMyCR(&status, 0);
                    v91_localTextRenderer.selectMyTR(&status, 2);
                }
                break;
                case 1: {
                    v91_localTextRenderer.selectMyCR(&status, 1);
                    v91_localTextRenderer.selectMyTR(&status, 2);
                }
                break;
                case 2: {
                    v91_localTextRenderer.selectMyCR(&status, 2);
                    v91_localTextRenderer.selectMyTR(&status, 2);
                }
                break;
                case 3: {
                    v91_localTextRenderer.selectMyCR(&status, 3);
                    v91_localTextRenderer.selectMyTR(&status, 3);
                }
                break;
                default: break;
                }
                AABB textAabb;
                memset(&textAabb, 0, sizeof(textAabb));
                v91_localTextRenderer.renderText2(
                    &status,
                    &v96_aabs[btnsCount],
                    *v23_pMbstr,
                    &g_FontObj1_instance,
                    &textAabb);
                int v34_btnIdx = btnsCount;
                textAabb.minX -= 8;
                textAabb.minY -= 8;
                textAabb.maxX += 8;
                textAabb.maxY += 8;
                this->aabb17_x16x30[a3_x16Idx][btnsCount] = textAabb;
                Size2i size {textAabb.maxX - textAabb.minX, textAabb.maxY - textAabb.minY};
                v93_sizes[v34_btnIdx] = {
                    6 * (size.w + 16),
                    size.h + 16
                };
                v22_curBtnInfo = a4_curBtnInfo + 1;
                ++btnsCount;
                ++a4_curBtnInfo;
            }
        } while (v22_curBtnInfo->btnId);
    }
    if (btnsCount) {
        Size2i v78_totalSize {0, 0};
        for (int i = 0; i < btnsCount; ++i) {
            Size2i &sz = v93_sizes[i];
            if (sz.w <= v78_totalSize.w) continue;
            v78_totalSize.w = sz.w;
        }
        for (int i = 0; i < btnsCount; ++i) {
            v78_totalSize.h += v93_sizes[i].h;
        }

        MySurface v94_localSurf;
        MySurface *v44_surf = v94_localSurf.constructor(&v78_totalSize, &g_confSurfDesc, NULL, 0);
        MySurface *surf66_x16 = &this->surf66_x16[a3_x16Idx];
        this->surf66_x16[a3_x16Idx] = *v44_surf;
        this->surf66_x16[a3_x16Idx].allocSurfaceIfNot(&status);
        memset(
            this->surf66_x16[a3_x16Idx].lpSurface,
            0,
            this->surf66_x16[a3_x16Idx].dwHeight * this->surf66_x16[a3_x16Idx].lPitch);
        int v68_posY = 0;
        for (int btnIdx = 0; btnIdx < btnsCount; ++btnIdx) {
            Size2i *v67_pSize = &v93_sizes[btnIdx];

            Size2i v51_sz {(int) ((v67_pSize->w - 16*6) / 6u + 16), v67_pSize->h};

            int v70_endY = v68_posY + v67_pSize->h;
            int v48_posX = 0;
            for (int j = 0; j < 6; ++j) {
                AABB *area = &this->aabb16_x16x30x6[a3_x16Idx][btnIdx][j];
                int endX = v48_posX + v51_sz.w;
                area->minX = v48_posX;
                area->maxX = endX;
                area->minY = v68_posY;
                area->maxY = v70_endY;

                MySurface *surf = &this->surf64_x16x30x6[a3_x16Idx][btnIdx][j];
                surf66_x16->copyAreaTo(&status, surf, area);
                v48_posX = endX;
            }
            v68_posY = v70_endY;

            PixelMask v72_pixMask;
            v72_pixMask.b = 0xBF;
            v72_pixMask.g = 0xBF;
            v72_pixMask.r = 0xBF;
            v72_pixMask.f3 = 0xFF;
            v72_pixMask.f4 = 0;
            g_FontObj1_instance.setFontMask(&status, &v72_pixMask);

            MySurface *v46_textSurf = &this->surf64_x16x30x6[a3_x16Idx][btnIdx][4];
            MySurface_probably_set_global_bitnes(v46_textSurf);
            switch (v96_rendererTyArr[btnIdx]) {
            case 0: {
                v91_localTextRenderer.selectMyCR(&status, 0);
                v91_localTextRenderer.selectMyTR(&status, 2);
            }
            break;
            case 1: {
                v91_localTextRenderer.selectMyCR(&status, 1);
                v91_localTextRenderer.selectMyTR(&status, 2);
            }
            break;
            case 2: {
                v91_localTextRenderer.selectMyCR(&status, 2);
                v91_localTextRenderer.selectMyTR(&status, 2);
            }
            break;
            case 3: {
                v91_localTextRenderer.selectMyCR(&status, 3);
                v91_localTextRenderer.selectMyTR(&status, 3);
            }
            break;
            default: break;
            }
            AABB v77_aabb;
            v77_aabb.minX = 8;
            v77_aabb.minY = 8;
            v77_aabb.maxX = v51_sz.w - 8;
            v77_aabb.maxY = v51_sz.h - 8;
            v91_localTextRenderer.renderText(&status, &v77_aabb, v94_mbStringArr[btnIdx], &g_FontObj1_instance, NULL);

            MySurface *hoverSurf = v46_textSurf + 1;
            MySurface_probably_set_global_bitnes(hoverSurf);
            g_FontObj1_instance.setFontMask(&status, &this->fontMask_3031E);
            v91_localTextRenderer.renderText(&status, &v77_aabb, v94_mbStringArr[btnIdx], &g_FontObj1_instance, NULL);

            MySurface *maxGlowSurf = v46_textSurf - 1;
            this->cglow.sub_5524F0(&status, maxGlowSurf, v46_textSurf, 3, &this->fontMask_30323);
            for (int j = 0; j < 3; ++j) {
                MySurface *glowSurf_ = &this->surf64_x16x30x6[a3_x16Idx][btnIdx][j];
                float a5a = (double) (j + 1) * 0.25;
                this->cglow.sub_552620(&status, glowSurf_, maxGlowSurf, a5a);
            }
        }
        g_FontObj1_instance.checkFlag8(&status);
    }
    v98_try_level = -1;
    v91_localTextRenderer.destructor();
    return 1;
}


char dk2::CFrontEndComponent::bakeButton(int a2_wndId, unsigned __int8 x16Idx, int a4_fontTy) {
    int status;

    Size2i btnSizes[30];
    uint8_t *mbStringArr[30];
    int f34_idxHigh0Arr[30];
    AABB btnAabbArr[30];

    uint8_t textRenderer_buf[sizeof(MyTextRenderer)];
    MyTextRenderer &textRenderer = *(MyTextRenderer*) textRenderer_buf;

    textRenderer.constructor();

    int v88_tryLevel = 0;
    int v6 = 30;
    AABB *aabb_ = &btnAabbArr[0];
    do {
        aabb_->minX = 0;
        aabb_->minY = 0;
        aabb_->maxX = 0;
        aabb_->maxY = 0;
        aabb_++;
        --v6;
    } while (v6);
    Pos2i *v7 = (Pos2i*) btnSizes;
    int v8 = 30;
    do {
        v7->x = 0;
        v7->y = 0;
        ++v7;
        --v8;
    } while (v8);
    switch (a4_fontTy) {
    case 1: g_FontObj1_instance.assign_constructor(&g_FontObj1_instance);
        break;
    case 2: g_FontObj1_instance.assign_constructor(&g_FontObj2_instance);
        break;
    case 3: g_FontObj1_instance.assign_constructor(&g_FontObj3_instance);
        break;
    case 4: g_FontObj1_instance.assign_constructor(&g_FontObj4_instance);
        break;
    case 5: g_FontObj1_instance.assign_constructor(&g_FontObj5_instance);
        break;
    case 6: g_FontObj1_instance.assign_constructor(&g_FontObj6_instance);
        break;
    case 7: g_FontObj1_instance.assign_constructor(&g_FontObj7_instance);
        break;
    case 8: g_FontObj1_instance.assign_constructor(&g_FontObj8_instance);
        break;
    case 9: g_FontObj1_instance.assign_constructor(&g_FontObj9_instance);
        break;
    default: break;
    }
    memset(btnSizes, 0, sizeof(btnSizes));
    g_FontObj1_instance.reset_f10(&status);
    unsigned __int8 btnsCount = 0;
    for (
        CButton *_buttons = this->cgui_manager.findGameWindowById(a2_wndId)->f66_buttons;
        _buttons;
        _buttons = _buttons->f78_next
    ) {
        if ((char (__cdecl *)(CButton *, CFrontEndComponent *)) _buttons->f24_renderFun != CClickButton_render_532670) continue;
        if (_buttons->f6F_kind != BT_CClickButton) continue;
        if (_buttons->f2C_textId == 0) continue;

        uint8_t *btnText_1 = MyMbStringList_idx1091_getMbString(_buttons->f2C_textId);

        mbStringArr[btnsCount] = btnText_1;
        AABB *btnAabb_1 = &btnAabbArr[btnsCount];
        AABB screenAabb;
        AABB *ScreenAABB = _buttons->getScreenAABB(&screenAabb);
        btnAabb_1->minX = ScreenAABB->minX;
        btnAabb_1->minY = ScreenAABB->minY;
        btnAabb_1->maxX = ScreenAABB->maxX;
        btnAabb_1->maxY = ScreenAABB->maxY;
        AABB aabb;
        *btnAabb_1 = *this->cgui_manager.scaleAabb_2560_1920(&aabb, btnAabb_1);
        uint16_t alignTy = LOWORD(_buttons->f34_idxHigh);
        f34_idxHigh0Arr[btnsCount] = alignTy;
        switch (alignTy) {
        case 0: {
            textRenderer.selectMyCR(&status, 0);
            textRenderer.selectMyTR(&status, 2);
        } break;
        case 1: {
            textRenderer.selectMyCR(&status, 1);
            textRenderer.selectMyTR(&status, 2);
        } break;
        case 2: {
            textRenderer.selectMyCR(&status, 2);
            textRenderer.selectMyTR(&status, 2);
        } break;
        case 3: {
            textRenderer.selectMyCR(&status, 3);
            textRenderer.selectMyTR(&status, 3);
        } break;
        default: break;
        }
        AABB textAabb;
        memset(&textAabb, 0, sizeof(textAabb));
        textRenderer.renderText2(&status, btnAabb_1, (char *) btnText_1, &g_FontObj1_instance, &textAabb);

        // Add margin 8 px
        textAabb.minX -= 8;
        textAabb.minY -= 8;
        textAabb.maxX += 8;
        textAabb.maxY += 8;

        // Assign new AABB
        this->aabb17_x16x30[x16Idx][btnsCount] = textAabb;
        Size2i size {textAabb.maxX - textAabb.minX, textAabb.maxY - textAabb.minY};
        btnSizes[btnsCount] = {
            6 * (size.w + 16),
            size.h + 16
        };
        ++btnsCount;
    }

    // Calc all buttons vbox width
    int surfWidth = 0;
    Size2i *curBtnMid = btnSizes;
    if (btnsCount) {
        int v24 = btnsCount;
        do {
            if (curBtnMid->w > surfWidth)
                surfWidth = curBtnMid->w;
            ++curBtnMid;
            --v24;
        } while (v24);
    }

    // Calc all buttons vbox height
    LONG surfHeight = 0;
    if (btnsCount) {
        Size2i *p_h = &btnSizes[0];
        int v27 = btnsCount;
        do {
            int y = p_h->h;
            p_h++;
            surfHeight += y;
            --v27;
        } while (v27);
    }

    Size2i surfSize {surfWidth, surfHeight};
    MySurface localSurf;
    MySurface *templateSurf = localSurf.constructor(&surfSize, &g_confSurfDesc, NULL, 0);
    MySurface *curSurf1 = &this->surf66_x16[x16Idx];
    MySurface *curSurf2 = &this->surf66_x16[x16Idx];
    memcpy(&this->surf66_x16[x16Idx], templateSurf, sizeof(MySurface));
    this->surf66_x16[x16Idx].allocSurfaceIfNot(&status);
    memset(
        this->surf66_x16[x16Idx].lpSurface,
        0,
        this->surf66_x16[x16Idx].dwHeight * this->surf66_x16[x16Idx].lPitch);
    int posY_ = 0;
    if (btnsCount) {
        int btnIdx = 0;
        Size2i *v56_size = &btnSizes[0];
        int idx = btnsCount;
        while (1) {
            MySurface_probably_set_global_bitnes(curSurf1);
            Size2i _sz {(v56_size->w - 16*6) / 6 + 16, v56_size->h};

            int endY_ = posY_ + _sz.h;
            int posX = 0;
            for (int j = 0; j < 6; ++j) {
                AABB *area = &this->aabb16_x16x30x6[x16Idx][btnIdx][j];
                int minY = posY_;
                int endX = posX + _sz.w;
                area->minX = posX;
                area->minY = minY;
                area->maxX = endX;
                area->maxY = endY_;

                MySurface *surf = &this->surf64_x16x30x6[x16Idx][btnIdx][j];
                curSurf2->copyAreaTo(&status, surf, area);
                posX = endX;
            }

            PixelMask v58_fontMask;
            v58_fontMask.b = 0xBF;
            v58_fontMask.g = 0xBF;
            v58_fontMask.r = 0xBF;
            v58_fontMask.f3 = 0xFF;
            v58_fontMask.f4 = 0;
            g_FontObj1_instance.setFontMask(&status, &v58_fontMask);

            MySurface *textSurf = &this->surf64_x16x30x6[x16Idx][btnIdx][4];
            MySurface_probably_set_global_bitnes(textSurf);
            switch (f34_idxHigh0Arr[btnIdx]) {
            case 0: {
                textRenderer.selectMyCR(&status, 0);
                textRenderer.selectMyTR(&status, 2);
            } break;
            case 1: {
                textRenderer.selectMyCR(&status, 1);
                textRenderer.selectMyTR(&status, 2);
            } break;
            case 2: {
                textRenderer.selectMyCR(&status, 2);
                textRenderer.selectMyTR(&status, 2);
            } break;
            case 3: {
                textRenderer.selectMyCR(&status, 3);
                textRenderer.selectMyTR(&status, 3);
            } break;
            default: break;
            }
            AABB textAabb;
            textAabb.minX = 8;
            textAabb.minY = 8;
            textAabb.maxX = _sz.w - 8;
            textAabb.maxY = _sz.h - 8;
            textRenderer.renderText(&status, &textAabb, mbStringArr[btnIdx], &g_FontObj1_instance, NULL);

            MySurface *hoverSurf = textSurf + 1;
            MySurface_probably_set_global_bitnes(hoverSurf);
            g_FontObj1_instance.setFontMask(&status, &this->fontMask_3031E);
            textRenderer.renderText(&status, &textAabb, mbStringArr[btnIdx], &g_FontObj1_instance, NULL);

            PixelMask a5_pixelMask;  // yellow color for glowing
            a5_pixelMask.b = 0;
            a5_pixelMask.g = 0xA8;
            a5_pixelMask.r = 0xFF;
            a5_pixelMask.f3 = 0xFF;
            a5_pixelMask.f4 = 0;
            MySurface *maxGlowSurf = textSurf - 1;
            this->cglow.sub_5524F0(&status, maxGlowSurf, textSurf, 3, &a5_pixelMask);
            for (int j = 0; j < 3; ++j) {
                MySurface *glowSurf = &this->surf64_x16x30x6[x16Idx][btnIdx][j];
                float a4c = (double) (j + 1) * 0.25;
                this->cglow.sub_552620(&status, glowSurf, maxGlowSurf, a4c);
            }

            posY_ = endY_;
            ++btnIdx;
            ++v56_size;
            --idx;
            if (idx == 0)
                break;
            curSurf1 = curSurf2;
        }
    }
    g_FontObj1_instance.checkFlag8(&status);
    v88_tryLevel = -1;
    textRenderer.destructor();
    return 1;
}

int __cdecl dk2::CButton_render_42A160(CButton *a1_btn, CDefaultPlayerInterface *a2_defplif) {
    int v14_try_level;

    AABB v13_tmp;
    Area4i pos = *(Area4i *) a2_defplif->cgui_manager.scaleAabb_2560_1920(&v13_tmp, (AABB *)&a1_btn->pos);

    PixelMask v11_pixelMask {0, 0, 0, 0, 0};
    if (a1_btn->f5D_isVisible != 1) return 0;

    unsigned __int8 v5_brightnes;
    if ( !a1_btn->f34_idxHigh || (v5_brightnes = -1, !a1_btn->f45_containsCursor) )
        v5_brightnes = -56;

    v11_pixelMask = {v5_brightnes, v5_brightnes, v5_brightnes, 0, 0};

    int value = MyResources_instance.video_settings.texture_reduction_level;

    if (value == 0) {
        v14_try_level = -1;
        unsigned __int8* v8_mbstr = MyMbStringList_idx1091_getMbString(0x5A2u);
        return a2_defplif->sub_42CB60(
            &a2_defplif->_options,
            pos.x, pos.y, v8_mbstr,
            &v11_pixelMask,
            0x11, 0, FontObj_3_instance, 1);
    }
    if (value == 1) {
        v14_try_level = -1;
        unsigned __int8* MbString = MyMbStringList_idx1091_getMbString(0x119u);
        return a2_defplif->sub_42CB60(
            &a2_defplif->_options,
            pos.x, pos.y, MbString,
            &v11_pixelMask,
            0x11, 0, FontObj_3_instance, 1);
    }
    if (value == 2) {
        v14_try_level = -1;
        unsigned __int8* v6_mbstr = MyMbStringList_idx1091_getMbString(0x5A3u);
        return a2_defplif->sub_42CB60(
            &a2_defplif->_options,
            pos.x, pos.y, v6_mbstr,
            &v11_pixelMask,
            0x11, 0, FontObj_3_instance, 1);
    }
    return value - 2;
}

