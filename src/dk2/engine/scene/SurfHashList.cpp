//
// Created by DiaLight on 1/22/2026.
//

#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2/SurfHashList.h"
#include "dk2/RenderStageTex.h"
#include "dk2/MyCESurfHandle.h"
#include "dk2/SurfHashListItem.h"
#include "dk2/CEngineSurfaceBase.h"
#include "dk2/CEngineSurface.h"
#include "patches/big_resolution_fix/big_resolution_fix.h"
#include "patches/logging.h"


namespace dk2 {

    int _calcWeight(RenderStageTex *self) {
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
    RenderStageTex * SurfQuadTree_findMinValueHolder(dk2::SurfHashList* self) {
        if(!self->stageTexs_first) return NULL;
        RenderStageTex* minValueItem = self->stageTexs_first;
        int minValue = 0x10000;
        if(patch::big_resolution_fix::enabled) {
            minValue = 0x1000000;
        }
        for (RenderStageTex* cur = self->stageTexs_first; cur; cur = cur->prev_) {
            int value = _calcWeight(cur);
            if (value == 0) return cur;
            if (value < minValue) {
                minValue = value;
                minValueItem = cur;
            }
        }
        return minValueItem;
    }
    void SurfQuadTree_detachHolder(dk2::SurfHashList* self, RenderStageTex* cur) {
        // detach all surf from holder
        for (MyCESurfHandle * surf = cur->surfh_first; surf; surf = cur->surfh_first) {
            cur->surfh_first = surf->nextByHolder;
            surf->nextByHolder = NULL;
            surf->holder_parent = NULL;
        }
        // end

        self->deleteItem(cur->hashItem_link);

        // detach from linked list
        if (RenderStageTex * next = cur->next_) next->prev_ = cur->prev_;
        if (RenderStageTex * prev = cur->prev_) prev->next_ = cur->next_;
        if(!cur->next_) self->stageTexs_first = cur->prev_;  // tail detach condition
        cur->next_ = NULL;
        cur->prev_ = NULL;
        // end
        if(self->stageTexs_first == NULL) {
            patch::log::err("last holder was detached. looks like %d holders is not enough", self->stageTexs_count);
        }
    }
    MyCESurfHandle *_probablySort_selectReduction(MyCESurfHandle *curSurfh) {
        int reductionLevel = g_ReductionLevel;
        MyCESurfHandle *tmpSutfh = curSurfh;
        while ((reductionLevel > 0 || (tmpSutfh->reductionLevel_andFlags & 7) < MyDirectDraw_instance_devTexture.reductionLevel) && tmpSutfh->nextByReduction) {
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

void dk2::SurfHashList::_probablySort() {
    RenderStageTex* removedList = NULL;
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

            RenderStageTex *found = SurfQuadTree_findMinValueHolder(this);
            SurfQuadTree_detachHolder(this, found);

            // add to removed list
            found->prev_ = removedList;
            removedList = found;
            // end add to removed list

            isRemoveActed = 1;
        }
    } while (isRemoveActed);
    while(removedList) {
        RenderStageTex *remNext = removedList->prev_;
        if (this->stageTexs_first) this->stageTexs_first->next_ = removedList;
        removedList->next_ = NULL;
        removedList->prev_ = this->stageTexs_first;
        this->stageTexs_first = removedList;
        removedList = remNext;
    }
    // update flags
    while(this->surfh_first) {
        MyCESurfHandle* cur = this->surfh_first;
        cur->reductionLevel_andFlags &= ~0x10u;
        cur->curReduction->reductionLevel_andFlags &= ~8u;
        this->surfh_first = cur->nextByHashList;
    }
    ++SurfHashList_sortTick;
}


namespace dk2 {

    SurfHashListItem *_SurfHashListItem_constructor(
            RenderStageTex *stageTex,
            uint8_t x, uint8_t y, uint16_t width, uint16_t height
    ) {
        SurfHashListItem *newItem = (SurfHashListItem *) MyHeap_alloc(sizeof(SurfHashListItem));
        if (!newItem) return NULL;
        newItem->width_257 = width;
        newItem->height_257 = height;
        newItem->x = x;
        newItem->y = y;
        newItem->holder_link = stageTex;
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
    this->stageTexs_count = 0;
    for (int idx = 0; idx < count; ++idx) {
        RenderStageTex *stageTex = RenderStageTex_create(this->squareSide_size, this->pSurfDesc, 0);
        if (!stageTex) break;
        ++this->stageTexs_count;

        stageTex->next_ = NULL;
        stageTex->prev_ = this->stageTexs_first;

        if (RenderStageTex *oldStageTex = this->stageTexs_first)
            oldStageTex->next_ = stageTex;
        this->stageTexs_first = stageTex;

        SurfHashListItem *item = _SurfHashListItem_constructor(stageTex, 0, 0, this->squareSide_size, this->squareSide_size);
        stageTex->hashItem_link = item;
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
        surfh->setRenderStageTex(item->holder_link, (uint8_t) item->x, (uint8_t) item->y);

        RenderStageTex* pStageTex = item->holder_link;
        surfh->nextByHolder = pStageTex->surfh_first;
        pStageTex->surfh_first = surfh;

        surfh->reductionLevel_andFlags |= 0x200u;
        if (surfh->cesurf == NULL) surfh->resolveSurface();
        pStageTex->surf->paintSurf(surfh->cesurf, (uint8_t) item->x, (uint8_t) item->y);
        surfh->reductionLevel_andFlags &= ~0x200u;
        return;
    }
}

