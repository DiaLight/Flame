//
// Created by DiaLight on 27.12.2022.
//
#include "win32_gui_layout.h"


bool gui::initDPI() {
    HMODULE userDLL = LoadLibrary("User32.dll");
    if (userDLL) {
        typedef BOOL (WINAPI *SetProcessDpiAwarenessContext_fun)(DPI_AWARENESS_CONTEXT value);
        auto SetProcessDpiAwarenessContext = (SetProcessDpiAwarenessContext_fun) GetProcAddress(userDLL, "SetProcessDpiAwarenessContext");
        if (SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2)) return true;
    }


    HMODULE shcoreDLL = LoadLibrary("SHCORE.DLL");
    if (shcoreDLL) {
        typedef HRESULT(WINAPI *SetProcessDpiAwareness_fun)(PROCESS_DPI_AWARENESS);
        auto SetProcessDpiAwareness = (SetProcessDpiAwareness_fun) GetProcAddress(shcoreDLL, "SetProcessDpiAwareness");

        if (SetProcessDpiAwareness) {
            /* Try Windows 8.1+ version */
            if (SUCCEEDED(SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE))) return true;
        }
    }
    if (userDLL) {
        typedef BOOL(WINAPI *SetProcessDPIAware_fun)(void);
        auto SetProcessDPIAware = (SetProcessDPIAware_fun) GetProcAddress(userDLL, "SetProcessDPIAware");
        if (SetProcessDPIAware) {
            /* Try Vista - Windows 8 version.
            This has a constant scale factor for all monitors.
            */
            if (SetProcessDPIAware()) return true;
        }
    }
    return false;
}

HINSTANCE gui::g_hInst = nullptr;
int gui::g_dpi = USER_DEFAULT_SCREEN_DPI;

int gui::getDpi() {
    UINT dpiX = 0, dpiY;
    POINT pt = {1, 1};
    auto hMonitor = MonitorFromPoint(pt, MONITOR_DEFAULTTONEAREST);

    HMODULE shcoreDLL = LoadLibrary("SHCORE.DLL");
    if (shcoreDLL) {
        typedef HRESULT (STDAPICALLTYPE *GetDpiForMonitor_fun)(HMONITOR hmonitor, MONITOR_DPI_TYPE dpiType, UINT *dpiX, UINT *dpiY);
        auto GetDpiForMonitor = (GetDpiForMonitor_fun) GetProcAddress(shcoreDLL, "GetDpiForMonitor");
        if (GetDpiForMonitor) {
            if (SUCCEEDED(GetDpiForMonitor(hMonitor, MDT_EFFECTIVE_DPI, &dpiX, &dpiY))) {
                return dpiX;
            }
        }
    }
    return 96; // default
}

int gui::applyDpi(int size) {
    return MulDiv(size, g_dpi, USER_DEFAULT_SCREEN_DPI);
}

int gui::revertDpi(int size) {
    return MulDiv(size, USER_DEFAULT_SCREEN_DPI, g_dpi);
}

void gui::applyDpi(gui::size2i_t &size) {
    size.w = applyDpi(size.w);
    size.h = applyDpi(size.h);
}

void gui::applyDpi(gui::pos2i_t &pos) {
    pos.x = applyDpi(pos.x);
    pos.y = applyDpi(pos.y);
}

HMENU gui::gui_elem_t::nextId = (HMENU) 1;


void gui::resizeWin(HWND hwnd, int width, int height) {
    RECT rect = {0, 0, applyDpi(width), applyDpi(height)};
    AdjustWindowRectEx(&rect, GetWindowStyle(hwnd), GetMenu(hwnd) != NULL, GetWindowExStyle(hwnd));
    size2i_t winSize = {rect.right - rect.left, rect.bottom - rect.top};
    pos2i_t winPos = {
            (GetSystemMetrics(SM_CXSCREEN) - winSize.w) / 2,
            (GetSystemMetrics(SM_CYSCREEN) - winSize.h) / 2
    };
    SetWindowPos(
            hwnd, HWND_TOP,
            winPos.x, winPos.y, winSize.w, winSize.h,
            SWP_NOCOPYBITS | SWP_NOACTIVATE | SWP_NOZORDER
    );
}

void gui::initLayout(HINSTANCE hInstance) {
    initDPI();
    g_dpi = getDpi();
    g_hInst = hInstance;
}
