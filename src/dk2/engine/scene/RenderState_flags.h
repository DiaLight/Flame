//
// Created by DiaLight on 7/31/2026.
//

#ifndef FLAME_RENDERSTATE_FLAGS_H
#define FLAME_RENDERSTATE_FLAGS_H

#define RenderState_alphaBlendOne       0x0001
#define RenderState_fl2                 0x0002

#define RenderState_alphaBlendSrc       0x0020
#define RenderState_useLightSplat       0x0040
#define RenderState_zWriteEnable        0x0080
#define RenderState_zEnable             0x0100
#define RenderState_use3DPipeline       0x0200
#define RenderState_linearFiltering     0x0400
#define RenderState_fl800               0x0800
#define RenderState_alphaBlendInvSrc    0x1000
#define RenderState_fl2000              0x2000
#define RenderState_diffuseAlpha        0x4000
#define RenderState_bumpMapSimple       0x8000
#define RenderState_bumpMapLuminance   0x10000

#endif //FLAME_RENDERSTATE_FLAGS_H
