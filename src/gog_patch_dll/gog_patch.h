//
// Created by DiaLight on 10.09.2024.
//

#ifndef FLAME_GOG_PATCH_H
#define FLAME_GOG_PATCH_H

#include <Windows.h>
#include <tools/flame_config.h>

extern flame_config::define_flame_option<bool> o_gog_enabled;
namespace gog {

    namespace RtGuiView_fix {
        bool isEnabled();
    }
    namespace SurfaceHolder_setTexture_patch {
        bool isEnabled();
    }

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
