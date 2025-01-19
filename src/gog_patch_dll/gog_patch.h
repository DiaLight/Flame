//
// Created by DiaLight on 10.09.2024.
//

#ifndef FLAME_GOG_PATCH_H
#define FLAME_GOG_PATCH_H

#include <Windows.h>

namespace gog {

    namespace RtGuiView_fix {
        bool isEnabled();
    }
    namespace SurfaceHolder_setTexture_patch {
        bool isEnabled();
    }

    extern bool enable;
    bool patch_init();

    namespace RegistryConfig_patch {
        bool isEnabled();
    }
    namespace parseCommandLine_patch {
        bool isEnabled();
    }
    namespace BullfrogWindow_proc_patch {
        bool isEnabled();
        bool window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
    }
}

#endif //FLAME_GOG_PATCH_H
