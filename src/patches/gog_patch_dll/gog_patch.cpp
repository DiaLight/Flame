//
// Created by DiaLight on 11.09.2024.
//
#include "gog_patch.h"
#include "gog_globals.h"
#include "gog_debug.h"

bool gog::RtGuiView_fix::isEnabled() { return true; }
bool gog::SurfaceHolder_setTexture_patch::isEnabled() { return true; }

bool gog::enable = true;
bool gog::RegistryConfig_patch::isEnabled() { return gog::enable; }
bool gog::parseCommandLine_patch::isEnabled() { return gog::enable; }

bool gog::BullfrogWindow_proc_patch::isEnabled() { return gog::enable; }
bool gog::BullfrogWindow_proc_patch::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if (!isEnabled()) return false;
    switch (Msg) {
        case WM_KILLFOCUS:
            ShowWindow(gog::g_hWnd, SW_MINIMIZE);
            break;
        case WM_ACTIVATEAPP:
            if (wParam) {  // activated
                gog::g_isRendererPaused = false;
                gog_debug("Resumed Render");
            } else {  // deactivated
                gog::g_isRendererPaused = true;
                gog_debug("Paused Render");
            }
            break;
        case WM_MOUSEMOVE: return true;  // do not call original fun
    }
    if (gog::g_isRendererPaused && (0x100 <= Msg && Msg < 0x300)) return true;  // do not call original fun
    return false;
}
