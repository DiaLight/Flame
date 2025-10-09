//
// Created by DiaLight on 10/9/2025.
//

#include "show_wireframe.h"
#include <d3d.h>
#include <d3dtypes.h>
#include <dinput.h>
#include "dk2_globals.h"

namespace {
    DWORD g_modes_idx = 1;
    DWORD g_modes[] {
        D3DFILL_SOLID,
        D3DFILL_WIREFRAME,
        D3DFILL_POINT
    };

    void selectNext() {
        IDirect3DDevice3 *dev3 = dk2::mydd_triangles.d3d3_halDevice;
        if (dev3 == nullptr) {
            printf("show_wireframe failed. d3d3_halDevice == NULL\n");
            return;
        }
        // works only with gog patch
        dev3->SetRenderState(D3DRENDERSTATE_FILLMODE, g_modes[g_modes_idx++ % ARRAYSIZE(g_modes)]);
    }
}

void patch::show_wireframe::onKeyboard(DIDEVICEOBJECTDATA *data) {  // if dinput is used
    bool isPressed = (data->dwData & 0x80) != 0;
    DWORD keyCode = data->dwOfs;
    switch (keyCode) {
    case DIK_F12:
        if (isPressed) selectNext();
        break;
    }
}

void patch::show_wireframe::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
    case WM_KEYDOWN:
        switch (wParam) {
        case VK_F12:
            selectNext();
            break;
        }
        break;
    }
}
