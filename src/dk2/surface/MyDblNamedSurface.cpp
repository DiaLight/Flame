//
// Created by DiaLight on 4/4/2026.
//
#include "dk2/MyDblNamedSurface.h"
#include "dk2/MyScaledSurface.h"
#include "dk2/MyCESurfScale.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/MyStringHashMap_MyScaledSurface_entry.h"
#include "dk2_functions.h"
#include "dk2_globals.h"


dk2::MyScaledSurface *__cdecl dk2::MyDblNamedSurface_createPrescaled(int idx, int width8, int height8) {
    if (idx < 0 || idx >= MyEntryBuf_MyScaledSurface_instance.count)
        MyWindow_log_printf(&MyWindow_instance, "Invalid Material\n");
    if ((MyDirectDraw_instance.flags & 1) == 0) return MyEntryBuf_MyScaledSurface_instance.buf[idx];
    if (width8 > 128 || height8 > 128) return MyEntryBuf_MyScaledSurface_instance.buf[idx];

    MyScaledSurface *surfItem = MyEntryBuf_MyScaledSurface_instance.buf[idx];
    for (MyScaledSurface *cur = surfItem; cur; cur = cur->nextPrescaledItem) {
        MyCESurfHandle *v6 = cur->scaledSurfArr->surfScaledArr[0];
        if (v6->surfWidth8 == width8 && v6->surfHeight8 == height8)
            return cur;
    }
    char *f0_name = MyStringHashMap_MyScaledSurface_instance.entries.buf[surfItem->idx].name;
    char *surfName = MyCESurfHandle_getName(surfItem->scaledSurfArr->surfScaledArr[0]);
    char Buffer[1024];
    sprintf(Buffer, "%sPRESCALED_TO%dBY%d", f0_name, width8, height8);
    int flags = surfItem->flags | 0x800;

    MyDblNamedSurface newSurf;
    newSurf.surf.constructor_empty();
    newSurf.pNames = (const char **) &newSurf.prevName;
    newSurf.curName = Buffer;
    newSurf.prevName = surfName;
    newSurf.init1__height = 1;
    newSurf.flags = flags;
    newSurf.blWidth = width8;
    newSurf.blHeight = height8;
    memset(&newSurf.init0, 0, 16);
    newSurf.init1__width = 1;
    int newIdx = MyEntryBuf_MyScaledSurface_create(&newSurf, 0);
    if (newIdx < 0 || newIdx >= MyEntryBuf_MyScaledSurface_instance.count)
        MyWindow_log_printf(&MyWindow_instance, "Invalid Material\n");
    MyScaledSurface *newSurfItem = MyEntryBuf_MyScaledSurface_instance.buf[newIdx];
    newSurfItem->scaledSurfArr->surfScaledArr[0]->resolveSurface();
    newSurfItem->nextPrescaledItem = surfItem->nextPrescaledItem;
    surfItem->nextPrescaledItem = newSurfItem;
    return newSurfItem;
}
