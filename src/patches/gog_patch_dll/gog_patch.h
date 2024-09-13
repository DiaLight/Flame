//
// Created by DiaLight on 10.09.2024.
//

#ifndef FLAME_GOG_PATCH_H
#define FLAME_GOG_PATCH_H

#include <Windows.h>

namespace gog {

    extern bool enable;
    bool patch_init();

    namespace RtGuiView_fix {
        extern bool enable;
    }
    namespace RegistryConfig_patch {
        extern bool enable;
    }
    namespace parseCommandLine_patch {
        extern bool enable;
    }
    namespace SurfaceHolder_setTexture_patch {
        extern bool enable;
    }
    namespace BullfrogWindow_proc_patch {
        extern bool enable;
        bool window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam);
    }
}

#endif //FLAME_GOG_PATCH_H
