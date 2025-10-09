//
// Created by DiaLight on 10/5/2025.
//

#include "remember_window_location_and_size.h"
#include "tools/flame_config.h"


flame_config::define_flame_option<bool> o_no_initial_size(
    "flame:no-initial-size", flame_config::OG_Config,
    "Disable autoresize window\n"
    "Used only in windowed mode\n",
    false
);

namespace {
    POINT window_pos = {50, 50};
    POINT window_size = {0, 0};
    bool ignore_size = true;

    void initWindowSize(uint32_t w, uint32_t h) {
        if(window_size.x != 0 || window_size.y != 0) return;
        if(o_no_initial_size.get()) return;
        int screenWidth = GetSystemMetrics(SM_CXSCREEN);
        int screenHeight = GetSystemMetrics(SM_CYSCREEN);

        int height;
        int width;
        if(screenHeight < screenWidth) {
            height = screenHeight * 5 / 6;
            width = height * 12 / 9;
        } else {
            width = screenWidth * 5 / 6;
            height = width * 9 / 12;
        }
        window_size = {width, height};
    }
}

bool patch::remember_window_location_and_size::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
    case WM_DESTROY: {
        ignore_size = true;
        break;
    }
    case WM_MOVE: {
        RECT winRect;
        GetWindowRect(hWnd, &winRect);
        window_pos = {winRect.left, winRect.top};

        break;
    }
    case WM_SIZE: {
        if(!ignore_size) {
            RECT winRect;
            GetWindowRect(hWnd, &winRect);
            window_size = {winRect.right - winRect.left, winRect.bottom - winRect.top};
        }
        break;
    }
    }
    return false;
}
void patch::remember_window_location_and_size::patchWinLoc(int &xPos, int &yPos) {
    xPos = window_pos.x;
    yPos = window_pos.y;
}
void patch::remember_window_location_and_size::resizeWindow(HWND hWnd, uint32_t w, uint32_t h) {
    initWindowSize(w, h);
    if(window_size.x != 0 && window_size.y != 0) {
        SetWindowPos(hWnd, NULL, 0, 0, window_size.x, window_size.y, SWP_NOMOVE | SWP_NOZORDER);
    }
    ignore_size = false;
}

