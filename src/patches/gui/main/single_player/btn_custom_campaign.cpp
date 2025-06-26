//
// Created by DiaLight on 6/2/2025.
//

#include "win_custom_campaign.h"
#include <dk2_functions.h>
#include <dk2_globals.h>
#include <dk2/button/button_types.h>
#include <dk2/button/CButton.h>
#include <dk2/gui/visual_debug.h>
#include <dk2/gui/main/main_layout.h>
#include <patches/gui/button_id.h>

namespace patch {
    struct PrerenderCustomCampaignButton {
        dk2::MySurface _surf64_x16x30x6[6]{};
        dk2::AABB _aabb16_x16x30x6[6]{};
        dk2::AABB _aabb17_x16x30{};
        PrerenderCustomCampaignButton(dk2::CButton *btn, dk2::CFrontEndComponent *front) {
            // from 00533570 char bakeButton(int, uint8_t, int);
            int status;

            uint8_t textRenderer_buf[sizeof(dk2::MyTextRenderer)];
            dk2::MyTextRenderer &textRenderer = *(dk2::MyTextRenderer*) textRenderer_buf;
            textRenderer.constructor();

            dk2::g_FontObj1_instance.assign_constructor(&dk2::g_FontObj6_instance);
            dk2::g_FontObj1_instance.reset_f10(&status);

            uint8_t btnText_1[64];
            dk2::UniToMb_convert((wchar_t *) L"Custom Campaigns", btnText_1, sizeof(btnText_1));

            dk2::AABB screenAabb;
            btn->getScreenAABB(&screenAabb);
            dk2::AABB scaledAabb;
            front->cgui_manager.scaleAabb_2560_1920(&scaledAabb, &screenAabb);

            textRenderer.selectMyCR(&status, 2);
            textRenderer.selectMyTR(&status, 2);


            dk2::AABB textAabb;
            memset(&textAabb, 0, sizeof(textAabb));
            textRenderer.renderText2(&status, &scaledAabb, (char *) btnText_1, &dk2::g_FontObj1_instance, &textAabb);

            // Add margin 8 px
            textAabb.minX -= 8;
            textAabb.minY -= 8;
            textAabb.maxX += 8;
            textAabb.maxY += 8;


            // Assign new AABB
            _aabb17_x16x30 = textAabb;
            dk2::Size2i size {textAabb.maxX - textAabb.minX, textAabb.maxY - textAabb.minY};
            dk2::Size2i btnSize = {
                6 * (size.w + 16),
                size.h + 16
            };


            dk2::MySurface localSurf;
            localSurf.constructor(&btnSize, &dk2::g_confSurfDesc, NULL, 0);
            localSurf.allocSurfaceIfNot(&status);
            memset(
                localSurf.lpSurface,
                0,
                localSurf.dwHeight * localSurf.lPitch);
            dk2::MySurface_probably_set_global_bitnes(&localSurf);
            dk2::Size2i _sz {(btnSize.w - 16*6) / 6 + 16, btnSize.h};

            int posY_ = 0;
            int endY_ = posY_ + _sz.h;
            int posX = 0;
            for (int j = 0; j < 6; ++j) {
                dk2::AABB *area = &_aabb16_x16x30x6[j];
                int minY = posY_;
                int endX = posX + _sz.w;
                area->minX = posX;
                area->minY = minY;
                area->maxX = endX;
                area->maxY = endY_;

                dk2::MySurface *surf = &_surf64_x16x30x6[j];
                localSurf.copyAreaTo(&status, surf, area);
                posX = endX;
            }

            dk2::PixelMask v58_fontMask;
            v58_fontMask.b = 0xBF;
            v58_fontMask.g = 0xBF;
            v58_fontMask.r = 0xBF;
            v58_fontMask.f3 = 0xFF;
            v58_fontMask.f4 = 0;
            dk2::g_FontObj1_instance.setFontMask(&status, &v58_fontMask);

            dk2::MySurface *textSurf = &_surf64_x16x30x6[4];
            dk2::MySurface_probably_set_global_bitnes(textSurf);

            textRenderer.selectMyCR(&status, 2);
            textRenderer.selectMyTR(&status, 2);

            dk2::AABB textAabb2;
            textAabb2.minX = 8;
            textAabb2.minY = 8;
            textAabb2.maxX = _sz.w - 8;
            textAabb2.maxY = _sz.h - 8;
            textRenderer.renderText(&status, &textAabb2, btnText_1, &dk2::g_FontObj1_instance, NULL);

            dk2::MySurface *hoverSurf = textSurf + 1;
            dk2::MySurface_probably_set_global_bitnes(hoverSurf);
            dk2::g_FontObj1_instance.setFontMask(&status, &front->fontMask_3031E);
            textRenderer.renderText(&status, &textAabb2, btnText_1, &dk2::g_FontObj1_instance, NULL);

            dk2::PixelMask a5_pixelMask;  // yellow color for glowing
            a5_pixelMask.b = 0;
            a5_pixelMask.g = 0xA8;
            a5_pixelMask.r = 0xFF;
            a5_pixelMask.f3 = 0xFF;
            a5_pixelMask.f4 = 0;
            dk2::MySurface *maxGlowSurf = textSurf - 1;
            front->cglow.sub_5524F0(&status, maxGlowSurf, textSurf, 3, &a5_pixelMask);
            for (int j = 0; j < 3; ++j) {
                dk2::MySurface *glowSurf = &_surf64_x16x30x6[j];
                float a4c = (double) (j + 1) * 0.25;
                front->cglow.sub_552620(&status, glowSurf, maxGlowSurf, a4c);
            }

            // {  // debug
            //     printf("b=%X g=%X r=%X f3=%X f4=%X\n",
            //         front->fontMask_3031E.b,
            //         front->fontMask_3031E.g,
            //         front->fontMask_3031E.r,
            //         front->fontMask_3031E.f3,
            //         front->fontMask_3031E.f4
            //     );
            //     dump(*hoverSurf);
            // }

            dk2::g_FontObj1_instance.checkFlag8(&status);
            textRenderer.destructor();
        }
    };

    char __cdecl CClickButton_renderCustomCampaign(dk2::CButton *btn, dk2::CFrontEndComponent *front) {
        // from 00532670 char __cdecl CClickButton_render_532670(CButton *, CFrontEndComponent *);
        char result = dk2::g_initialized73E9D4;
        if (!dk2::g_initialized73E9D4) {
            dk2::g_initialized73E9D4 = 1;
            memset(dk2::d70D578_x30, 0, sizeof(dk2::d70D578_x30));
            memset(dk2::buttonHighlight_x30, 0, 30u);
            result = 0;
            memset(dk2::btnSoundLoaded_73E9A0_x30, 0, 30u);
        }
        uint16_t x16Idx = 5;  // Singleplayer
        uint16_t btnIdx = 4;

        static PrerenderCustomCampaignButton prerendered(btn, front);

        dk2::CButton *v3 = btn;
        if (btn->f5D_isVisible != 1)
            return result;
        dk2::CFrontEndComponent *frontend = front;

        front->arr_x16x30_hovered[x16Idx][btnIdx] = 0;
        dk2::AABB scaledBounds;
        dk2::AABB screenBounds = *v3->getScreenAABB(&scaledBounds);
        dk2::AABB *pScaledBounds = frontend->cgui_manager.scaleAabb_2560_1920(&scaledBounds, &screenBounds);
        dk2::AABB btnPos = *pScaledBounds;

        // dk2::calcBounds(alignTy, btnPos, x16Idx, btnIdx, frontend, scaledBounds);
        {
            auto &textSurf = prerendered._surf64_x16x30x6[4]; // regular text
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

        // calc hover score
        if (btn->f45_containsCursor) {
            auto mousePos = frontend->cgui_manager.mousePos;
            auto aabb22 = prerendered._aabb17_x16x30;
            if (mousePos.x >= aabb22.minX && mousePos.x < aabb22.maxX
                && mousePos.y >= aabb22.minY && mousePos.y < aabb22.maxY
            ) {
                if (!dk2::btnSoundLoaded_73E9A0_x30[btnIdx]) {
                    dk2::MySound_ptr->v_fun_567810(0, frontend->f5AB9, 783);
                    dk2::btnSoundLoaded_73E9A0_x30[btnIdx] = 1;
                }
                frontend->arr_x16x30_hovered[x16Idx][btnIdx] = 1;
                dk2::buttonHighlight_x30[btnIdx] = 8;
            }
        }

        // render hover glowing
        char highlightLevel = dk2::buttonHighlight_x30[btnIdx] - 1;
        dk2::buttonHighlight_x30[btnIdx] = highlightLevel;
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
                &prerendered._surf64_x16x30x6[layer],
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
            &prerendered._surf64_x16x30x6[layer2],
            NULL,
            0);

        highlightLevel = dk2::buttonHighlight_x30[btnIdx];
        if (highlightLevel < 0) {
            dk2::btnSoundLoaded_73E9A0_x30[btnIdx] = 0;
            dk2::buttonHighlight_x30[btnIdx] = -1;
        }
        return highlightLevel;
    }


    void __cdecl CButton_CustomCampaign_handleLeftClick(int a1_arg1, int a2_arg2, dk2::CFrontEndComponent *a3_frontend) {
        // inspired by 00538000 void __cdecl CButton_handleLeftClick_538000(int, int, CFrontEndComponent *);
        int status;
        int v3_curWindowId = MWID_SinglePlayer;
        int v5_nextWindowId = 0;
        int switchKey = 0;
        int btnIdx = 4;

        if (dk2::MyResources_instance.gameCfg.useFe2d_unk1 &&dk2::g_bg2d_loaded[dk2::g_surfIdx_6AD608] ) {
            static_MyDdSurfaceEx_BltWait(
               &status, a3_frontend->pMyDdSurfaceEx, 0, 0,
               &dk2::g_bg2d_surface[dk2::g_surfIdx_6AD608], NULL, 0
            );
        }
        if ( btnIdx == 255 || a3_frontend->arr_x16x30_hovered[dk2::windowId_to_x16Idx(v3_curWindowId)][btnIdx] ) {
            if ( v3_curWindowId ) {
                changeGui(0, v3_curWindowId, a3_frontend);
                if ( (uint16_t) v5_nextWindowId )
                    changeGui(1, (unsigned __int16)v5_nextWindowId, a3_frontend);
            }
            memset(a3_frontend->arr_x16x30_hovered, 0, sizeof(a3_frontend->arr_x16x30_hovered));
            switch ( switchKey ) {
            case 0:
                a3_frontend->playerIdx11 = 0;
                if (!dk2::MyResources_instance.gameCfg.useFe2d_unk1) {
                    dk2::CCamera *cam = a3_frontend->bridge->v_getCamera();
                    cam->flags_E3C |= 8u;
                    cam->loadEnginePath(0x10Fu, 2u, 0xCu, 1);
                }
                dk2::g_maybeGuiIsShowing = 0;
                dk2::g_pathAnimationEndSwitch = custom_campaign::animEndAction;
                break;
            }
        }
    }
}  // namespace patch

dk2::ButtonCfg patch::custom_campaign::SinglePlayer_CustomCampaign_btn(dk2::Area4s a1, dk2::Area4s a2) {
    uint16_t curWindowId = MWID_SinglePlayer;
    return { // Custom Campaign
        BT_CClickButton, dk2::BID_SinglePlayer_CustomCampaign, 0, CButton_CustomCampaign_handleLeftClick, NULL,
        0, 0, 0, 0, 0,
        a1.x, a1.y, (uint16_t) a1.w, (uint16_t) a1.h,
        (uint16_t) a2.x, (uint16_t) a2.y, (uint16_t) a2.w, (uint16_t) a2.h,
        0, NULL,
        CClickButton_renderCustomCampaign, NULL, 0, 0, 0,
        32
    }; // Custom Campaign

}
