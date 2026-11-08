//
// Created by DiaLight on 6/22/2026.
//

#include "dk2_functions.h"
#include "dk2_globals.h"
#include "opengl_patch.h"
#include "tools/visual_debug.h"


namespace dk2 {

    void init_example(int fontSize, int alignment) {
        int status;

        wchar_t wstring[64];
        swprintf(wstring, 64, L"Open GL");
        uint8_t mbstring[64];
        UniToMb_convert(wstring, mbstring, 64);

        uint8_t textRenderer_buf[sizeof(MyTextRenderer)];
        MyTextRenderer &textRenderer = *(MyTextRenderer*) textRenderer_buf;

        textRenderer.constructor();

        Bgraf color {0xBF, 0xBF, 0xBF, 0xFF, 0};
        g_FontObj1_instance.setColor(&status, &color);

        Size2i surfSize {200, 100};
        MySurface textSurf_;
        MySurface *textSurf = textSurf_.constructor(&surfSize, &g_confSurfDesc_bgra32, NULL, 0);
        textSurf->allocSurfaceIfNot(&status);

        MySurface maxGlowSurf_;
        MySurface *maxGlowSurf = maxGlowSurf_.constructor(&surfSize, &g_confSurfDesc_bgra32, NULL, 0);
        maxGlowSurf->allocSurfaceIfNot(&status);

        MySurface glowSurf_;
        MySurface *glowSurf = glowSurf_.constructor(&surfSize, &g_confSurfDesc_bgra32, NULL, 0);
        glowSurf->allocSurfaceIfNot(&status);

        MyNBitTexture_initWithSurf(textSurf);

        switch (fontSize) {
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

        switch (alignment) {
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
        Bgraf textColor {0xBF, 0xBF, 0xBF, 0xFF, 0};
        Bgraf color2 {0, 0xA8, 0xFF, 0xFF, 0};  // yellow color for glowing

        g_FontObj1_instance.setColor(&status, &textColor);

        AABB textAabb;
        textAabb.minX = 8;
        textAabb.minY = 8;
        textAabb.maxX = surfSize.w - 8;
        textAabb.maxY = surfSize.h - 8;
        textRenderer.renderText(&status, &textAabb, mbstring, &g_FontObj1_instance, NULL);
//        textRenderer.renderText2(&status, &textAabb, (char *) mbstring, &g_FontObj1_instance, NULL);

//        MySurface *hoverSurf = textSurf + 1;
//        MyNBitTexture_initWithSurf(hoverSurf);
//        g_FontObj1_instance.setColor(&status, &textColor);
//        textRenderer.renderText(&status, &textAabb, mbstring, &g_FontObj1_instance, NULL);

        auto &cglow = CFrontEndComponent_instance.cglow;
        cglow.sub_5524F0(&status, maxGlowSurf, textSurf, 3, &color2);

        float a4c = (double) 3 * 0.25;
        cglow.sub_552620(&status, glowSurf, maxGlowSurf, a4c);

        MySurface_static_copy(&status, textSurf, 0, 0, glowSurf, NULL, 0);

        if(patch::opengl_patch::enabled) {
            char tmp[64];
            snprintf(tmp, 64, "textSurf f=%d r=%d", fontSize, alignment);
            dump(*textSurf, tmp);
//            dump(*glowSurf, tmp);
        }
        maxGlowSurf->reset();
        glowSurf->reset();
        textSurf->reset();
    }

}

void example_text_render() {
    static bool init = false;
    if(!init) {
//        dk2::init_example(6, 0);
//        dk2::init_example(7, 0);
//        dk2::init_example(8, 0);
//        dk2::init_example(9, 0);
        init = true;
    }
}

