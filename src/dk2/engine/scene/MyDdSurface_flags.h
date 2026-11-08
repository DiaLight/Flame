//
// Created by DiaLight on 5/31/2026.
//

#ifndef FLAME_MYDDSURFACE_FLAGS_H
#define FLAME_MYDDSURFACE_FLAGS_H

#define MyDdSurface_screenSwap 0x01


#define MyDdSurface_unk02 0x02  // isFullscreen && !screenSwap
#define MyDdSurface_unk04 0x04

/*
 * Indicates that a surface may be a destination for 3D rendering.  This
 * bit must be set in order to query for a Direct3D Device Interface
 * from this surface.
 */
#define MyDdSurface_3DDEVICE 0x08  // DDSCAPS_3DDEVICE


#define MyDdSurface_isWindowed 0x10

/*
 * Indicates that this surface exists in video memory.
 */
#define MyDdSurface_videoMemory 0x20

#define MyDdSurface_FPUControlWord 0x40
#define MyDdSurface_extraBackBuffer 0x80



#endif //FLAME_MYDDSURFACE_FLAGS_H
