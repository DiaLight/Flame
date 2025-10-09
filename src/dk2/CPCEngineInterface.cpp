//
// Created by DiaLight on 9/19/2025.
//
#include <dk2/CPCEngineInterface.h>
#include "dk2/CEngineDDSurface.h"
#include "dk2/CEngineSurface.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/MyDblNamedSurface.h"
#include "dk2/SurfHashList.h"
#include "dk2/SurfHashList2.h"
#include "dk2/SurfHashListItem.h"
#include "dk2/SurfaceHolder.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/big_resolution_fix/big_resolution_fix.h"
#include "patches/external_textures.h"
#include "patches/logging.h"


int __cdecl dk2::mydd_devTexture_init(MyDirectDraw *mydd) {
    mydd_devTexture_destroy();
    // destruct if flag changed
    if ( ((mydd_devTexture.flags ^ mydd->flags) & 1) != 0 ) {
        for (MyCESurfHandle *i = g_surfh_first; i; i = i->gnext ) {
            if ( (i->reductionLevel_andFlags & 0x200) == 0 ) {
                if (i->cesurf) i->cesurf->v_scalar_destructor(1u);
                i->cesurf = NULL;
            }
        }
    }
    mydd_devTexture = *mydd;
    isSupports_4r4g4b4a = 0;
    isSupports_8r8g8b8a = 0;
    isSupports_16bit = 0;
    g_surfDesc_8a8r8g8b_0.constructor(0xFF000000, 0xFF0000u, 0xFF00u, 0xFFu, 32);
    if ((mydd_devTexture.flags & 1) != 0) {
        MyCEngineSurfDesc_argb32_instance.constructor(0xFF000000, 0xFF0000u, 0xFF00u, 0xFFu, 32);
        SurfHashList *obj = (SurfHashList *) MyHeap_alloc(sizeof(SurfHashList));
        SurfHashList *v7;
        if ( obj ) {
            for (int x = 0; x < 5; ++x) {
                for (int y = 0; y < 5; ++y) {
                    obj->arr5x5[x][y] = NULL;
                }
            }
            obj->f6C = 0;
            obj->holder_first = NULL;
            obj->holders_count = 0;
            obj->surfh_first = NULL;
            v7 = obj;
        } else {
            v7 = NULL;
        }
        pSurfHashList = v7;
        int numHolders = 24;
        if(patch::big_resolution_fix::enabled) {
            numHolders *= 4;
        }
        v7->constructor(&MyCEngineSurfDesc_argb32_instance, numHolders);
    } else {
        mydd_devTexture.d3d3_halDevice->EnumTextureFormats(
            (LPD3DENUMPIXELFORMATSCALLBACK) D3DENUMPIXELFORMATSCALLBACK_proc, 0);
        if (!isSupports_4r4g4b4a && !isSupports_8r8g8b8a) return 0;
        char v14 = 1;
        if (!isSupports_16bit) {
            mydd_devTexture.flags &= 0xFFCFu;
        } else {
            if ( (mydd_devTexture.flags & 0x30) != 0 ) {
                SurfHashList2 *v15 = (SurfHashList2 *) MyHeap_alloc(sizeof(SurfHashList2));
                SurfHashList2 *v20;
                if (v15) {
                    for (int y = 0; y < 5; ++y) {
                        for (int x = 0; x < 5; ++x) {
                            v15->arr5x5_surfh[x][y] = NULL;
                            v15->arr5x5[x][y] = NULL;
                        }
                    }
                    v15->f8count = 0;
                    v15->holder_first = NULL;
                    v15->holder_count = 0;
                    v15->surfh_first = NULL;
                    v15->ddsurf = NULL;
                    v20 = v15;
                } else {
                    v20 = NULL;
                }
                pSurfHashList2 = v20;
                v14 = v20->constructor(&MyCEngineSurfDesc_unk16_instance, 2, 2) & 1;
            }
            if (!isSupports_16bit) {
                mydd_devTexture.flags &= 0xFFCFu;
            }
        }
        SurfHashList2 *v21 = (SurfHashList2 *) MyHeap_alloc(sizeof(SurfHashList2));
        SurfHashList2 *v26;
        if ( v21 ) {
            for (int y = 0; y < 5; ++y) {
                for (int x = 0; x < 5; ++x) {
                    v21->arr5x5_surfh[x][y] = NULL;
                    v21->arr5x5[x][y] = NULL;
                }
            }
            v21->f8count = 0;
            v21->holder_first = NULL;
            v21->holder_count = 0;
            v21->surfh_first = NULL;
            v21->ddsurf = NULL;
            v26 = v21;
        } else {
            v26 = NULL;
        }
        pSurfHashList2_2 = v26;
        if ( ((unsigned __int8) v26->constructor(&MyCEngineSurfDesc_argb32_instance, 32, 512) & (unsigned __int8)v14) == 0 ) {
            SurfHashList2_initialized = 1;
            mydd_devTexture_destroy();
            return 0;
        }
    }
    if ( MyTextures_instance.f430 ) {
        MyTextures_instance.texNameToFileOffsetMap.cleanup();
        MyTextures_instance.f430 = 0;
        if ( MyTextures_instance.fileHandle )
            fclose(MyTextures_instance.fileHandle);
        MyTextures_instance.fileHandle = NULL;
    }
    MyTextures_instance.f430 = 1;
    int v29 = 0;
    if ( MyTextures_instance.rwfile.open(MyTextures_instance.textureCacheFile_dir, "TCHC", &v29) && v29 == 4 ) {
        int count = 0;
        MyTextures_instance.rwfile.readInt(&count, 4u);
        for (int k = 0; k < count; ++k) {
            void *value = NULL;
            char name[256];
            MyTextures_instance.rwfile.readString(name);
            MyTextures_instance.rwfile.readInt(&value, 4u);
            MyTextures_instance.texNameToFileOffsetMap.put(name, value);
        }
        MyTextures_instance.rwfile.sub_57A6F0();
    } else {
        patch::log::err("failed to open texture file TCHC");
    }
    MyTextures_instance.fileHandle = dk2::_fopen(MyTextures_instance.textureCacheFile_dat, "rb");
    if(!MyTextures_instance.fileHandle) {
        patch::log::err("failed to open texture cache file");
    }
    SurfHashList2_initialized = 1;
    CEngineSurface *v9 = (CEngineSurface *)MyHeap_alloc(0x18);
    CEngineSurface *v30 = v9;
    int try_level = 0;
    CEngineSurface *v10;
    if ( v9 ) {
        v10 = v9->constructor(128, 128, &g_surfDesc_8a8r8g8b_0);
    } else {
        v10 = NULL;
    }
    try_level = -1;
    CEngineSurfaceScaler_instance.orig_128x128_8a8r8g8b = v10;
    CEngineSurface *v11 = (CEngineSurface *) MyHeap_alloc(sizeof(CEngineSurface));
    v30 = v11;
    try_level = 1;
    CEngineSurface *v12;
    if ( v11 ) {
        v12 = v11->constructor(128, 128, &g_surfDesc_8a8r8g8b_0);
    } else {
        v12 = NULL;
    }
    CEngineSurfaceScaler_instance.scaled_128x128_8a8r8g8b = v12;
    patch::external_textures::dumpTextures();
    return 1;
}


int __cdecl dk2::mydd_scene_init(
    LPDIRECTDRAW dd, LPDIRECTDRAWSURFACE ddOffScreen, LPDIRECTDRAWSURFACE ddPrimarySurf,
    GUID *deviceGuid, __int16 flags, int isLowResTexture
) {
    MyDblNamedSurface testCrossSurf;
    MyDblNamedSurface whiteTextureSurf;
    MyDblNamedSurface testLightSurf;

    mydd_scene_destroy();
    is3dInitialized = 1;
    dd->QueryInterface(CLSID_IDirectDraw4, (LPVOID*) &mydd_scene);
    ddOffScreen->QueryInterface(CLSID_IDirectDrawSurface4, (LPVOID*) &mydd_scene.ddsurf4_offScreen);
    ddPrimarySurf->QueryInterface(
        CLSID_IDirectDrawSurface4,
        (LPVOID*) &mydd_scene.ddsurf4_primarySurf);
    mydd_scene.reductionLevel = isLowResTexture;
    mydd_scene.flags = flags;

    DDSURFACEDESC surfDesc;
    memset(&surfDesc, 0, sizeof(surfDesc));
    surfDesc.dwSize = sizeof(DDSURFACEDESC);
    static_assert(sizeof(DDSURFACEDESC) == 108);

    ddOffScreen->GetSurfaceDesc(&surfDesc);
    g_sceneWidth = surfDesc.dwWidth;
    g_sceneHeight = surfDesc.dwHeight;
    g2_sceneLeft = 0;
    g2_sceneTop = 0;
    g2_sceneWidth = surfDesc.dwWidth;
    g2_sceneHeight = surfDesc.dwHeight;
    if(patch::big_resolution_fix::enabled) {  // extend buffer size
        surfDesc.dwWidth = MyGame_instance.dwWidth;
        surfDesc.dwHeight = MyGame_instance.dwHeight;
    }
    if ((mydd_scene.flags & 1) != 0) {
        // Martin Griffiths MMX Software Renderer
        mydd_scene.buf = init_mgsr(ddOffScreen, &mydd_scene.buf2, surfDesc.dwWidth, surfDesc.dwHeight);
        grpoly_mydd_buf2 = mydd_scene.buf2;
        grpoly_mydd_buf = mydd_scene.buf;
        mgsr_buf2_width = 2 * g_sceneWidth;
        mgsr_buf_width = 4 * g_sceneWidth;
        mgsr_initialized = 1;
    } else {
        mydd_scene.dd4->QueryInterface(CLSID_IDirect3D3, (LPVOID*) &mydd_scene.d3d3);
        if (
            mydd_scene.d3d3->CreateViewport(&mydd_scene.d3d3_viewport, NULL) ||
            mydd_scene.d3d3->CreateDevice(CLSID_IDirect3DHALDevice, mydd_scene.ddsurf4_offScreen, &mydd_scene.d3d3_halDevice, NULL
        )) {
            mydd_scene_destroy();
            return 0;
        }
        mydd_scene.d3d3_halDevice->AddViewport(mydd_scene.d3d3_viewport);
        mydd_scene.d3d3_halDevice->SetCurrentViewport(mydd_scene.d3d3_viewport);
    }
    if (!configureFlagsAndTexturesCount() || !mydd_devTexture_init(&mydd_scene)) {
        mydd_scene_destroy();
        return 0;
    }
    if ((mydd_scene.flags & 2) != 0) {
        mydd_scene.ddsurf4_primarySurf->QueryInterface(
            CLSID_IDirectDrawGammaControl,
            (LPVOID*) &dd_gamma_control);
        if (is3dInitialized) {
            if ((mydd_scene.flags & 2) != 0)
                dd_gamma_control->SetGammaRamp(0, &gamma_ramp);
        }
    }
    mydd_triangles_init(&mydd_scene);
    mydd_uvs_init(&mydd_scene);
    shadows_init();
    testLightSurf.constructor("EngineTestLight", "EngineTestLight", 16, 0, 1);
    EngineTestLight_a31x400_idx = MyEntryBuf_MyScaledSurface_create(&testLightSurf, 1);
    testCrossSurf.constructor("EngineTestCross", "EngineTestCross", 16, 0, 1);
    EngineTestCross_a31x400_idx = MyEntryBuf_MyScaledSurface_create(&testCrossSurf, 1);
    whiteTextureSurf.constructor("EngineTextureWhite", "EngineTextureWhite", 0, 0, 1);
    EngineTextureWhite_a31x400_idx = MyEntryBuf_MyScaledSurface_create(&whiteTextureSurf, 1);
    g_isCurDdSurfLost = 0;
    return 1;
}


bool __cdecl dk2::engine_drawScene(char a1) {
    g_unk_765204 = 0;
    engine_setViewport(0, 0, g_sceneWidth, g_sceneHeight);
    if ((mydd_scene.flags & 1) != 0) {
        if (a1) {
            render_clearBuffers(
                g2_sceneWidth, g2_sceneHeight,
                &mydd_scene.buf[g_sceneWidth * g2_sceneTop + g2_sceneLeft],
                4 * g_sceneWidth,
                &mydd_scene.buf2[g_sceneWidth * g2_sceneTop + g2_sceneLeft],
                2 * g_sceneWidth);
            mgsr_drawMode = 0;
        } else {
            mgsr_drawMode ^= 1u;
        }
    } else {
        mydd_scene.d3d3_halDevice->BeginScene();
    }
    draw3dScene();
    draw_tex_to_buf();
    sub_578E80();
    if (g_unk_6BDEB8 < 0) {
        shadows_dword_780E70 = 0;
    } else {
        shadows_dword_780E70 = 1;
        sub_593640(
            g_unk_6BDEB8,
            g_camState.leftRight.x - -20.0,
            g_camState.leftRight.y - 20.0,
            g_camState.topBottom.x - -20.0,
            g_camState.topBottom.y - 20.0
        );
    }
    if ((mydd_scene.flags & 1) != 0) {
        DDSURFACEDESC2 surfDesc;
        surfDesc.dwSize = sizeof(DDSURFACEDESC2);
        static_assert(sizeof(DDSURFACEDESC2) == 124);
        RECT rect {0, 0, g_sceneWidth, g_sceneHeight};
        if (!mydd_scene.ddsurf4_offScreen->Lock(&rect, &surfDesc, 0x801, NULL)) {
            if (surfDesc.ddpfPixelFormat.dwRGBBitCount <= 16) {
                drawToSurface_mgsr(
                    (int) &mydd_scene.buf[g_sceneWidth * g2_sceneTop + g2_sceneLeft],
                    (int) surfDesc.lpSurface + 2 * g2_sceneLeft + g2_sceneTop * surfDesc.lPitch,
                    g2_sceneWidth, g2_sceneHeight,
                    4 * g_sceneWidth,
                    surfDesc.lPitch,
                    (int) &mydd_scene.buf2[g_sceneWidth * g2_sceneTop + g2_sceneLeft],
                    2 * g_sceneWidth,
                    0, 0);
            } else {
                drawToSurface32bit(
                    (int) &mydd_scene.buf[g_sceneWidth * g2_sceneTop + g2_sceneLeft],
                    (int) surfDesc.lpSurface + 2 * g2_sceneLeft + g2_sceneTop * surfDesc.lPitch,
                    g2_sceneWidth, g2_sceneHeight,
                    4 * g_sceneWidth,
                    surfDesc.lPitch,
                    &mydd_scene.buf2[g_sceneWidth * g2_sceneTop + g2_sceneLeft],
                    2 * g_sceneWidth,
                    0, 0);
            }
            mydd_scene.ddsurf4_offScreen->Unlock(NULL);
        }
    } else {
        mydd_scene.d3d3_halDevice->EndScene();
    }
    g_unk_75CA88 = g_unk_765B10;
    sub_576010();
//    void* v1;
//    ret_void_0args_0(v1);
    ++g_drawSceneCount_76520C;
    return g_isCurDdSurfLost == 0;
}

void __cdecl dk2::engine_set_g2_screenArea(int posX, int posY, int width, int height) {
    g2_sceneLeft = posX;
    g2_sceneTop = posY;
    g2_sceneWidth = width;
    g2_sceneHeight = height;
    if(patch::big_resolution_fix::enabled) {  // don make screen area bigger than buffer size
        size_t bufWidth = client_rect.right - client_rect.left;
        size_t bufHeight = client_rect.bottom - client_rect.top;
        if(bufWidth != 0 && bufHeight != 0) {
            if(g2_sceneWidth > bufWidth) g2_sceneWidth = bufWidth;
            if(g2_sceneHeight > bufHeight) g2_sceneHeight = bufHeight;
        }
    }
}
int dk2::SurfaceHolder::calcWeight() {
    int weight = 0;
    for (MyCESurfHandle *cur = this->surfh_first; cur; cur = cur->nextByHolder) {
        int bufSize = cur->surfWidth8 * cur->surfHeight8;
        if ((cur->reductionLevel_andFlags & 0x10) != 0) {
            weight += 4 * bufSize;
        } else {
            int ticks = SurfHashList_sortTick - cur->sortTick;
            if (ticks <= 0) {
                weight += bufSize;
            } else {
                weight += bufSize * (2 / (ticks + 1) + 1);
            }
        }
    }
    return weight;
}

namespace dk2 {

    int _calcWeight(SurfaceHolder *self) {
        // reductionLevel_andFlags
        // 0x07: reduction level
        // 0x10: added to SurfHashList
        // 0x80: empty texture
        // 0x100: use padding 0.5  // 00591D2A
        int weight = 0;
        for (MyCESurfHandle* cur = self->surfh_first; cur; cur = cur->nextByHolder) {
            int bufSize = cur->surfWidth8 * cur->surfHeight8;
            if ((cur->reductionLevel_andFlags & 0x10) != 0) {  // added to SurfHashList
                weight += 4 * bufSize;
            } else {
                int ticks = SurfHashList_sortTick - cur->sortTick;
                if (ticks <= 0) {
                    weight += bufSize;
                } else {
                    weight += bufSize * (2 / (ticks + 1) + 1);
                }
            }
        }
        return weight;
    }

    inline int SurfQuadTree_sizeToBucket(dk2::SurfHashList* self, size_t size) {
//        if(patch::big_resolution_fix::enabled) {  // checks for bucket hits
//            if(size > 256) {
//                patch::log::dbg("fix size %d\n", size);
//                size = 256;
//            }
//        }
        int bucket = SurfQuadTree_size257_to_bucket5[size];
//        if(patch::big_resolution_fix::enabled) {  // checks for bucket hits
//            if(bucket < 0) {
//                patch::log::dbg("fix bucket %d\n", bucket);
//                bucket = 0;
//            }
//            if(bucket > 4) {
//                patch::log::dbg("fix bucket %d\n", bucket);
//                bucket = 4;
//            }
//        }
        return bucket;
    }
    bool SurfQuadTree_put(dk2::SurfHashList* self, MyCESurfHandle* surfh) {
        int bucketX = SurfQuadTree_sizeToBucket(self, surfh->surfWidth8);
        int bucketY = SurfQuadTree_sizeToBucket(self, surfh->surfHeight8);
        // 44444444444444444
        // [4332222111111110000000000000000]
        // small - 4; big = 0
        for (int dx = 0; dx < 5; ++dx) {
            for(int dy = 0; dy <= dx; ++dy) {
                // big - small
                // 0 1 4 9
                // . 3 6 B
                // . . 8 D
                // . . . F
                {
                    int x = bucketX - dx;
                    int y = bucketY - dy;
                    if (x >= 0 && y >= 0) {
                        if (SurfHashListItem *item = self->arr5x5[x][y]) {
                            self->expandPut(surfh, item);
                            return true;
                        }
                    }
                    if (x >= 0 && y <= 0) break;
                }
                if(dy != dx) {
                    // . . . .
                    // 2 . . .
                    // 5 7 . .
                    // A B E .
                    int x = bucketX - dy;
                    int y = bucketY - dx;
                    if (x >= 0 && y >= 0) {
                        if (SurfHashListItem *item = self->arr5x5[x][y]) {
                            self->expandPut(surfh, item);
                            return true;
                        }
                    }
                }
            }
        }
        return false;
    }
    SurfaceHolder * SurfQuadTree_findMinValueHolder(dk2::SurfHashList* self) {
        if(!self->holder_first) return NULL;
        SurfaceHolder* minValueItem = self->holder_first;
        int minValue = 0x10000;
        if(patch::big_resolution_fix::enabled) {
            minValue = 0x1000000;
        }
        for (SurfaceHolder* cur = self->holder_first; cur; cur = cur->prev_) {
            int value = _calcWeight(cur);
            if (value == 0) return cur;
            if (value < minValue) {
                minValue = value;
                minValueItem = cur;
            }
        }
        return minValueItem;
    }
    void SurfQuadTree_detachHolder(dk2::SurfHashList* self, SurfaceHolder* cur) {
        // detach all surf from holder
        for (MyCESurfHandle * surf = cur->surfh_first; surf; surf = cur->surfh_first) {
            cur->surfh_first = surf->nextByHolder;
            surf->nextByHolder = NULL;
            surf->holder_parent = NULL;
        }
        // end

        self->deleteItem(cur->hashItem_link);

        // detach from linked list
        if (SurfaceHolder * next = cur->next_) next->prev_ = cur->prev_;
        if (SurfaceHolder * prev = cur->prev_) prev->next_ = cur->next_;
        if(!cur->next_) self->holder_first = cur->prev_;  // tail detach condition
        cur->next_ = NULL;
        cur->prev_ = NULL;
        // end
        if(self->holder_first == NULL) {
            patch::log::err("last holder was detached. looks like %d holders is not enough", self->holders_count);
        }
    }
    MyCESurfHandle *_probablySort_selectReduction(MyCESurfHandle *curSurfh) {
        int reductionLevel = g_ReductionLevel;
        MyCESurfHandle *tmpSutfh = curSurfh;
        while ((reductionLevel > 0 || (tmpSutfh->reductionLevel_andFlags & 7) < mydd_devTexture.reductionLevel) && tmpSutfh->nextByReduction) {
            tmpSutfh = tmpSutfh->nextByReduction;
            --reductionLevel;
        }
        curSurfh->curReduction = tmpSutfh;
        return tmpSutfh;
    }
}
void dk2::SurfHashList::deleteItem(SurfHashListItem *item) {
    for (int x = 0; x < 2; ++x) {
        for (int y = 0; y < 2; ++y) {
            if (SurfHashListItem *cur = item->quadtree2x2[x][y]) {
                this->deleteItem(cur);
                int bucketX = SurfQuadTree_sizeToBucket(this, cur->width_257);
                int bucketY = SurfQuadTree_sizeToBucket(this, cur->height_257);

                // detach from linked list
                if (SurfHashListItem * next = cur->next)
                    next->prev = cur->prev;
                if (SurfHashListItem * prev = cur->prev)
                    prev->next = cur->next;
                if(!cur->next) this->arr5x5[bucketX][bucketY] = cur->prev;  // tail detach condition
                cur->prev = NULL;
                cur->next = NULL;
                // end

                if (SurfHashListItem *v8 = cur->quadtree2x2[0][0])
                    v8->recursive_scalar_delete(1);
                if (SurfHashListItem *v9 = cur->quadtree2x2[1][0])
                    v9->recursive_scalar_delete(1);
                if (SurfHashListItem *v10 = cur->quadtree2x2[0][1])
                    v10->recursive_scalar_delete(1);
                if (SurfHashListItem *v11 = cur->quadtree2x2[1][1])
                    v11->recursive_scalar_delete(1);
                MyHeap_free(cur);
                item->quadtree2x2[x][y] = NULL;
            }
        }
    }
    if (!item->_aBool) {
        item->_aBool = 1;
        putNode(item);
    }
}

int dk2::SurfHashList::_probablySort() {
    SurfaceHolder* removedList = NULL;
    int isRemoveActed;
    do {
        isRemoveActed = 0;
        for (MyCESurfHandle * cur = this->surfh_first; cur;) {
            MyCESurfHandle *reducted = _probablySort_selectReduction(cur);
            if (reducted->holder_parent) {
                cur = cur->nextByHashList;
                continue;
            }

            if (SurfQuadTree_put(this, reducted)) {
                cur = cur->nextByHashList;
                continue;
            }

            SurfaceHolder *found = SurfQuadTree_findMinValueHolder(this);
            SurfQuadTree_detachHolder(this, found);

            // add to removed list
            found->prev_ = removedList;
            removedList = found;
            // end add to removed list

            isRemoveActed = 1;
        }
    } while (isRemoveActed);
    while(removedList) {
        SurfaceHolder *remNext = removedList->prev_;
        if (this->holder_first) this->holder_first->next_ = removedList;
        removedList->next_ = NULL;
        removedList->prev_ = this->holder_first;
        this->holder_first = removedList;
        removedList = remNext;
    }
    // update flags
    while(this->surfh_first) {
        MyCESurfHandle* cur = this->surfh_first;
        cur->reductionLevel_andFlags &= ~0x10u;
        cur->curReduction->reductionLevel_andFlags &= ~8u;
        this->surfh_first = cur->nextByHashList;
    }
    return ++SurfHashList_sortTick;
}


namespace dk2 {

    SurfHashListItem *_SurfHashListItem_constructor(
        SurfaceHolder *holder,
        uint8_t x, uint8_t y, uint16_t width, uint16_t height
    ) {
        SurfHashListItem *newItem = (SurfHashListItem *) MyHeap_alloc(sizeof(SurfHashListItem));
        if (!newItem) return NULL;
        newItem->width_257 = width;
        newItem->height_257 = height;
        newItem->x = x;
        newItem->y = y;
        newItem->holder_link = holder;
        newItem->next = NULL;
        newItem->prev = NULL;
        newItem->quadtree2x2[0][0] = NULL;
        newItem->quadtree2x2[1][0] = NULL;
        newItem->quadtree2x2[0][1] = NULL;
        newItem->quadtree2x2[1][1] = NULL;
        newItem->_aBool = 1;
        return newItem;
    }

}

void dk2::SurfHashList::constructor(MyCEngineSurfDesc *desc, int count) {
    this->pSurfDesc = desc;
    this->squareSide_size = 256;
    this->holders_count = 0;
    for (int idx = 0; idx < count; ++idx) {
        SurfaceHolder *holder = SurfaceHolder_create(this->squareSide_size, this->pSurfDesc, 0);
        if (!holder) break;
        ++this->holders_count;

        holder->next_ = NULL;
        holder->prev_ = this->holder_first;

        if (SurfaceHolder * oldHolder = this->holder_first)
            oldHolder->next_ = holder;
        this->holder_first = holder;

        SurfHashListItem * item = _SurfHashListItem_constructor(holder, 0, 0, this->squareSide_size, this->squareSide_size);
        holder->hashItem_link = item;
        this->putNode(item);
    }
}

void dk2::SurfHashList::putNode(SurfHashListItem *item) {
    int bucketX = SurfQuadTree_sizeToBucket(this, item->width_257);
    int bucketY = SurfQuadTree_sizeToBucket(this, item->height_257);
    SurfHashListItem ** pItem = &this->arr5x5[bucketX][bucketY];
    // attach to list
    if (SurfHashListItem * oldItem = *pItem)
        oldItem->next = item;
    item->prev = *pItem;
    // end
    *pItem = item;
}

namespace dk2 {

    SurfHashListItem * SurfQuadTree_expandVertical(SurfHashList* self, SurfHashListItem* item) {
        SurfHashListItem * top = _SurfHashListItem_constructor(
            item->holder_link,
            (uint8_t) item->x, item->y,
            item->width_257, item->height_257 >> 1);
        SurfHashListItem * bot = _SurfHashListItem_constructor(
            item->holder_link,
            (uint8_t) item->x, item->y + (item->height_257 >> 1),
            item->width_257, item->height_257 >> 1);

        item->quadtree2x2[0][0] = top;
        item->quadtree2x2[0][1] = bot;

        self->putNode(top);
        self->putNode(bot);
        return top;
    }
    SurfHashListItem * SurfQuadTree_expandHorisontal(dk2::SurfHashList* self, SurfHashListItem* item) {
        SurfHashListItem * left = _SurfHashListItem_constructor(
            item->holder_link,
            (uint8_t) item->x, (uint8_t) item->y,
            item->width_257 >> 1, item->height_257);
        SurfHashListItem * right = _SurfHashListItem_constructor(
            item->holder_link,
            (uint8_t) item->x + (item->width_257 >> 1), item->y,
            item->width_257 >> 1, item->height_257);

        item->quadtree2x2[0][0] = left;
        item->quadtree2x2[1][0] = right;

        self->putNode(left);
        self->putNode(right);
        return left;
    }

    SurfHashListItem * SurfQuadTree_expandAll(dk2::SurfHashList* self, SurfHashListItem* item) {
        SurfHashListItem * topLeft = _SurfHashListItem_constructor(
            item->holder_link,
            item->x, (uint8_t) item->y,
            item->width_257 >> 1, item->height_257 >> 1);
        SurfHashListItem * topRight = _SurfHashListItem_constructor(
            item->holder_link,
            (item->width_257 >> 1) + (uint8_t) item->x, item->y,
            item->width_257 >> 1, item->height_257 >> 1);
        SurfHashListItem * botLeft = _SurfHashListItem_constructor(
            item->holder_link,
            (uint8_t) item->x, (item->height_257 >> 1) + item->y,
            item->width_257 >> 1, item->height_257 >> 1);
        SurfHashListItem * botRight = _SurfHashListItem_constructor(
            item->holder_link,
            (uint8_t) (item->width_257 >> 1) + (uint8_t) item->x, (item->height_257 >> 1) + item->y,
            item->width_257 >> 1, item->height_257 >> 1);

        item->quadtree2x2[0][0] = topLeft;
        item->quadtree2x2[1][0] = topRight;
        item->quadtree2x2[0][1] = botLeft;
        item->quadtree2x2[1][1] = botRight;

        self->putNode(topLeft);
        self->putNode(topRight);
        self->putNode(botLeft);
        self->putNode(botRight);
        return topLeft;
    }
}

void dk2::SurfHashList::expandPut(MyCESurfHandle *surfh, SurfHashListItem *item) {
    int expectBucketX = SurfQuadTree_sizeToBucket(this, surfh->surfWidth8);
    int expectBucketY = SurfQuadTree_sizeToBucket(this, surfh->surfHeight8);

    while (true) {
        int bucketX = SurfQuadTree_sizeToBucket(this, item->width_257);
        int bucketY = SurfQuadTree_sizeToBucket(this, item->height_257);

        // detach item from linked list
        if (SurfHashListItem * next = item->next)
            next->prev = item->prev;
        if (SurfHashListItem * prev = item->prev)
            prev->next = item->next;
        if(!item->next) this->arr5x5[bucketX][bucketY] = item->prev;  // tail detach condition
        item->prev = NULL;
        item->next = NULL;
        item->_aBool = 0;
        // end of detach

        if (bucketX != expectBucketX && bucketY != expectBucketY) {
            item = SurfQuadTree_expandAll(this, item);
            continue;
        }
        if (bucketX != expectBucketX && bucketY == expectBucketY) {
            item = SurfQuadTree_expandHorisontal(this, item);
            continue;
        }
        if (bucketX == expectBucketX && bucketY != expectBucketY) {
            item = SurfQuadTree_expandVertical(this, item);
            continue;
        }
        surfh->setSurfaceHolder(item->holder_link, (uint8_t) item->x, (uint8_t) item->y);

        SurfaceHolder* holder = item->holder_link;
        surfh->nextByHolder = holder->surfh_first;
        holder->surfh_first = surfh;

        surfh->reductionLevel_andFlags |= 0x200u;
        if (surfh->cesurf == NULL) surfh->resolveSurface();
        ((CEngineSurfaceBase*) holder->ddsurf)->paintSurf(surfh->cesurf, (uint8_t) item->x, (uint8_t) item->y);
        surfh->reductionLevel_andFlags &= ~0x200u;
        return;
    }
}

