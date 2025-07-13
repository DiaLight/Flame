//
// Created by DiaLight on 3/30/2025.
//
#include <dk2_globals.h>
#include <dk2_functions.h>
#include <dk2/dk2_memory.h>
#include <dk2/MySurface.h>
#include <patches/logging.h>
#include <patches/micro_patches.h>


dk2::MySurface *__cdecl dk2::MyResources_loadPng(const char *name) {
    char Buffer[1024];
    if (!MyResources_instance.gameCfg.EnableArtPatching) {
        sprintf(Buffer, "Attempt To Load PNG without artpatch : %s", name);
        patch::log::dbg("%s", Buffer);
    }
    MySurface *surf = g_pCBridge->v_loadPng(name);
    if (patch::null_surf_fix::enabled) {
        if (surf == NULL) {
            surf = &patch::null_surf_fix::emptySurf;
            patch::log::dbg("[fix] tried to load \"%s\" PNG but NULL returned. replace with empty texture", name);
        }
    }
    return surf;
}
