//
// Created by DiaLight on 10.09.2024.
//
#include "dk2/CDefaultPlayerInterface.h"
#include "dk2/MessageData.h"
#include "dk2/entities/CPlayer.h"
#include "dk2/entities/CCreature.h"
#include "dk2/entities/CObject.h"
#include "dk2/entities/CTrap.h"
#include "dk2/entities/data/MyObjectDataObj.h"
#include "dk2/entities/data/MyTrapDataObj.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/micro_patches.h"
#include "gog_patch.h"
#include "dk2/entities/entities_type.h"
#include "patches/drop_thing_from_hand_fix.h"
#include "tools/bug_hunter.h"


int dk2::CDefaultPlayerInterface::tickKeyboard2() {
    int v18_try_catch;

    Pos2i *MousePos = MyGame_instance.getMousePos();
    int x = MousePos->x;
    int y = MousePos->y;
    int controlKeyFlags = MyInputManagerCb_static_buildControlFlags();
    int v15_isLControl = isActionKeyPressed(20, controlKeyFlags, 1);  // DIK_LCONTROL
    int v5_isLShift = isActionKeyPressed(21, controlKeyFlags, 1);  // DIK_LSHIFT
    int v13_isLShift = v5_isLShift;
    int ignoreModifiers = 0;
    if (v15_isLControl || v5_isLShift) ignoreModifiers = 1;
    int dwWidth = MyGame_instance.dwWidth;
    int dwHeight = MyGame_instance.dwHeight;

    if (!control_windowed_mode::enabled) {
        if (x < 5)
            this->pushMoveKeyAction(0, 0);
        if (x > dwWidth - 5)
            this->pushMoveKeyAction(1, 0);
        if (y < 5)
            this->pushMoveKeyAction(2, 0);
        if (y > dwHeight - 5)
            this->pushMoveKeyAction(3, 0);
    }

    if (!v15_isLControl) {
        int v8_isLShift = v13_isLShift;
        if (isActionKeyPressed(18, controlKeyFlags, ignoreModifiers)) {  // DIK_LEFT
            if (MyResources_instance.playerCfg.isAlternativeScroll) {
                __int16 v7 = this->playerTagId;
                GameAction v17_action;
                v17_action.data1 = -64;
                v17_action.data2 = 0.0;
                v17_action.data3 = 0;
                v17_action.actionKind = 8;
                v17_action._playerTagId = v7;
                v18_try_catch = 0;
                this->pushAction(&v17_action);
                v18_try_catch = -1;
            } else {
                this->pushMoveKeyAction(0, v13_isLShift);
            }
        }
        if (isActionKeyPressed(19, controlKeyFlags, ignoreModifiers)) {  // DIK_RIGHT
            if (MyResources_instance.playerCfg.isAlternativeScroll) {
                __int16 f8__cpyToF10 = this->playerTagId;
                GameAction v17_action;
                v17_action.data1 = 64;
                v17_action.data2 = 0.0;
                v17_action.data3 = 0;
                v17_action.actionKind = 8;
                v17_action._playerTagId = f8__cpyToF10;
                v18_try_catch = 1;
                this->pushAction(&v17_action);
                v18_try_catch = -1;
            } else {
                this->pushMoveKeyAction(1, v8_isLShift);
            }
        }
        if (isActionKeyPressed(16, controlKeyFlags, ignoreModifiers))  // DIK_UP
            this->pushMoveKeyAction(2, v8_isLShift);
        if (isActionKeyPressed(17, controlKeyFlags, ignoreModifiers))  // DIK_DOWN
            this->pushMoveKeyAction(3, v8_isLShift);
    }
    int result = this->f1094;
    if (!result && !this->f1098)
        return 0;
    GameAction v17_action;
    v17_action.actionKind = 3;
    v17_action.data1 = ((result * MyResources_instance.playerCfg.scrollSpeed) << 6) / 10;
    int v11 = (MyResources_instance.playerCfg.scrollSpeed * this->f1098) << 6;
    v17_action.data2 = (v11 / 10);
    v17_action.data3 = 0;
    v17_action._playerTagId = this->playerTagId;
    v18_try_catch = 2;
    return this->pushAction(&v17_action);
}


void dk2::CDefaultPlayerInterface::createSurfacesForView_42CDF0(RtGuiView *view) {
    CBridge *f10_c_bridge = this->profiler->c_bridge;
    char *rowPos = (char *) view->surf.lpSurface;
    int v4_bytesPerPix = view->dwRGBBitCount / 8;
    int v13_lineSize = 32 * view->surf.lPitch;
    char *v10__allyWindowText = (char *) view->surf.lpSurface;
    for (unsigned int y = 0; y < view->height_32blocks; ++y) {
        char *linePos = rowPos;
        for (unsigned int x = 0; x < view->width_128blocks; ++x) {
            int lPitch = view->surf.lPitch;
            Pos2i v14_size;
            v14_size.x = 128;
            v14_size.y = 32;
            MySurface v15_surf;
            v15_surf.constructor(&v14_size, &view->surf.desc, linePos, lPitch);
            int _idx = x + view->width_128blocks * y;
            if (gog::RtGuiView_fix::isEnabled()) {
                if (idx >= 93 && view == &dk2::CDefaultPlayerInterface_instance._allyWindowText) {
                    idx = 0;
                }
            }
            int _id = view->Arrp31x400_ids[_idx];
            f10_c_bridge->v_f68(_id, &v15_surf, 1);
            linePos += v4_bytesPerPix * 128;
        }
        rowPos = &v10__allyWindowText[v13_lineSize];
        v10__allyWindowText += v13_lineSize;
    }
}

void __cdecl dk2::CDefaultPlayerInterface_chatCallback(
        void *a1,
        MessageData *a2_message,
        CDefaultPlayerInterface *a3_defPlayerIf) {
    int playerFlag = 1 << ((CPlayer *) sceneObjects[a3_defPlayerIf->playerTagId])->playerNumber;
    uint32_t sendPlayerFlags = ((a2_message->flags_playerMask & 0x7FFF0000) >> 1) | a2_message->flags_playerMask & 0x7FFF;
    if ((sendPlayerFlags & playerFlag) == 0) return;  // this message is not for you

    MyChatMessage *hist = a3_defPlayerIf->chatHistory;
    for (int i = 0; i < 2; ++i) {
        memcpy(&hist[i], &hist[i + 1], 0x102u);
    }

    if (fix_chat_buffer_invalid_memory_access::enabled) {
        size_t strLen = wcslen((wchar_t *) &a2_message->sendTarget);  // whole message concept is being wchar_t[] compatible zero terminated string
        size_t strSize = 2 * strLen + 2;  // precise message buffer size
        memset(&a3_defPlayerIf->chatHistory[2].sendTarget, 0, 0x102u);
        if (strSize > 0x102u) strSize = 0x102u;
        memcpy(&a3_defPlayerIf->chatHistory[2].sendTarget, &a2_message->sendTarget, strSize);  // don't read behind allocated buffer
    } else {
        memcpy(&a3_defPlayerIf->chatHistory[2].sendTarget, &a2_message->sendTarget, 0x102u);
    }
    int expireTime = getTimeMs() + 30000;
    a3_defPlayerIf->chatHistory[2].expireTime = expireTime;
    a3_defPlayerIf->chatUpdated = 1;
}


BOOL __cdecl dk2::CDefaultPlayerInterface_onMouseAction(
        int a1_KeyCode_F0toF3,
        unsigned int a2_isPressed,
        Pos2i a3_coord,
        CDefaultPlayerInterface *a4_dplif) {
    CBridge *f10_c_bridge = a4_dplif->profiler->c_bridge;
    CCamera *a4_dplifa = f10_c_bridge->v_getCamera();
    if ( a4_dplif->cgui_manager.f18 ) return 1;
    CCamera *v6_camera = f10_c_bridge->v_getCamera();
    BOOL result = v6_camera->isInputAllowed();
    if ( !result ) return result;
    if ( a4_dplif->fFD
         || a4_dplifa->_mode != 7
            && a4_dplif->is3dEngineNe1
            && a4_dplifa->fun_44D620()
            && (a4_dplifa->_mode != 2 || a4_dplif->inMenu)
            && !a4_dplif->f10C
            && (a4_dplif->cgui_manager.fun_52C0A0(a3_coord, a1_KeyCode_F0toF3, a2_isPressed)
                || a4_dplif->sub_41FCF0(a3_coord.x, a3_coord.y, a1_KeyCode_F0toF3, a2_isPressed))
         || a4_dplif->profiler->inMenu ) {
        return 1;
    }
    Pos2i v8_coord = a3_coord;
    a4_dplif->sub_40BFF0(&v8_coord, 0);
    if ( a1_KeyCode_F0toF3 == 0xF0 ) {
        a4_dplif->handleLeftClick(a2_isPressed, &a4_dplif->_underHand);
    } else {
        if ( a1_KeyCode_F0toF3 == 0xF1 ) {
            // underHand filled here 0040BFF0 -> 005992B0
            a4_dplif->handleRightClick(a2_isPressed, &a4_dplif->_underHand);
            return 1;
        }
        if ( a1_KeyCode_F0toF3 == 0xF2 && a4_dplif->f10C ) {
            a4_dplif->f10C = 0;
            return 1;
        }
    }
    return 1;
}

namespace dk2 {
    bool scheduleDropNextTick(CDefaultPlayerInterface *self, ObjUnderHand *a3_underHand) {
        if (!self->thingsInHand_count) return false;
        CPI_ThingInHand *thingInHand = nullptr;
        for (int i = 0; i < self->thingsInHand_count; ++i) {
            CPI_ThingInHand *cur = &self->thingsInHand[i];
            if (cur->hasUnderHand) continue;
            thingInHand = cur;
            break;
        }
        if(thingInHand == nullptr) return false;
        if (self->checkAllowToDrop((CThing *) sceneObjects[thingInHand->tagId], a3_underHand->x, a3_underHand->y)) {
            thingInHand->hasUnderHand = 1;
            static_assert(sizeof(ObjUnderHand) == 0x22);
            memcpy(&thingInHand->underHand, a3_underHand, sizeof(ObjUnderHand));
        }
        return true;
    }
}

void dk2::CDefaultPlayerInterface::handleRightClick(unsigned int a2_isPressed, ObjUnderHand *a3_underHand) {
    int v43_try;
    MyProfiler *f4_profiler = this->profiler;
    CBridge *f10_c_bridge = f4_profiler->c_bridge;
    this->pCWorld->v_getCTag_508C40(this->playerTagId);
    unsigned int cameraMode = f10_c_bridge->v_fCC();
    if (cameraMode == 7) {
        this->cgui_manager.sub_52CCB0();
        if (a2_isPressed) {
            GameAction v38_act;
            v38_act.data1 = 3;
            v38_act.data2 = 0;
            v38_act.data3 = 0;
            v38_act.actionKind = 15;
            v38_act._playerTagId = this->playerTagId;
            v43_try = 0;
            this->pushAction(&v38_act);
            v43_try = -1;
            this->cgui_manager.unkObj = 0;
        }
        this->pCWorld->v_loc_508D00(0);
        CWorld *f53_pCWorld = this->pCWorld;
        int v10_height = f53_pCWorld->v_getCMapHeight_508FB0();
        int v10_width = f53_pCWorld->v_getCMapWidth_508FA0();
        f53_pCWorld->v_loc_508CC0(0, 0, v10_width, v10_height);
        return;
    }
    if (this->f10C) this->f10C = 0;
    if ((cameraMode == 2 || cameraMode == 1) && !this->inMenu) {
        if ((Obj6F2550_instance.f407 & 1) == 0 || !a2_isPressed) return;
        GameAction v38_act;
        v38_act.data1 = 0;
        v38_act.data2 = 0;
        v38_act.data3 = this->playerTagId;
        v38_act.actionKind = 21;  // __Posessed___ReleaseCreature
        v38_act._playerTagId = this->playerTagId;
        v43_try = 1;
        this->pushAction(&v38_act);
        v43_try = -1;
        this->sub_4094C0();
        return;
    }
    if (cameraMode == 11) {
        GameAction v38_act;
        v38_act.data1 = this->playerTagId;
        v38_act.data2 = 0;
        v38_act.data3 = 0;
        v38_act.actionKind = 22;
        v38_act._playerTagId = this->playerTagId;
        v43_try = 2;
        this->pushAction(&v38_act);
        return;
    }
    if (cameraMode == 10) return;
    if (this->_someTy) {
        if (a2_isPressed) this->sub_4094C0();
        return;
    }
    if (!a2_isPressed) return;
    if (!this->hasThingsInHand(this->playerTagId)) {
        switch (a3_underHand->type) {
            case 2u: {  // your CCreature
                unsigned int f1C_type = ((CCreature *) sceneObjects[a3_underHand->tagId])->sub_4918B0(this->playerTagId);
                if (!f1C_type) return;
                unsigned __int16 fD84_direction = this->profiler->c_bridge->v_getCamera()->direction;
                GameAction v38_act;
                v38_act.data1 = a3_underHand->tagId;
                v38_act.data2 = fD84_direction;
                v38_act.data3 = 0;
                v38_act.actionKind = 62;  // SlapCreature
                v38_act._playerTagId = this->playerTagId;
                v43_try = 3;
                this->pushAction(&v38_act);
            } break;
            case 3u: {  // others CCreature
                CCreature *creature = (CCreature *) sceneObjects[a3_underHand->tagId];
                BOOL belongsToPlayer = creature->_belongsTo(this->playerTagId);
                unsigned __int16 v24_playerTagId = this->playerTagId;
                if (belongsToPlayer) {
                    unsigned int f1C_type = creature->sub_4918B0(v24_playerTagId);
                    if (f1C_type) {
                        unsigned __int16 v25_camDirection = this->profiler->c_bridge->v_getCamera()->direction;
                        GameAction v39_act;
                        v39_act.data1 = a3_underHand->tagId;
                        v39_act.data2 = v25_camDirection;
                        v39_act.data3 = 0;
                        v39_act.actionKind = 62;  // SlapCreature
                        v39_act._playerTagId = this->playerTagId;
                        v43_try = 4;
                        this->pushAction(&v39_act);
                        v43_try = -1;
                        this->ingameCursor.sub_40ABC0(11, 0);
                    }
                } else {
                    int v29_playerMask = 1 << (((CPlayer *) sceneObjects[v24_playerTagId])->playerNumber - 1);
                    unsigned __int16 f3F7_highPriorityBody = creature->highPriorityBody;
                    GameAction v40_act;
                    v40_act.data3 = 0;
                    v40_act.actionKind = 106;  // MarkCreature
                    v40_act._playerTagId = v24_playerTagId;
                    v40_act.data1 = a3_underHand->tagId;
                    v40_act.data2 = (unsigned __int16) (f3F7_highPriorityBody & v29_playerMask) == 0;
                    v43_try = 5;
                    this->pushAction(&v40_act);
                }
            } return;
            case 4u: {  // CObject
                unsigned int f1C_type = ((CObject *) sceneObjects[a3_underHand->tagId])->typeObj->flags;
                if ((f1C_type & 0x200) == 0) return;
                unsigned __int16 v30_camDirection = this->profiler->c_bridge->v_getCamera()->direction;
                GameAction v41_act;
                v41_act.data2 = v30_camDirection;
                v41_act.data1 = a3_underHand->tagId;
                v41_act.data3 = 0;
                v41_act.actionKind = 63;  // SlapObject
                v41_act._playerTagId = this->playerTagId;
                v43_try = 6;
                this->pushAction(&v41_act);
            } break;
            case 7u: {  // CTrap
                CTrap *trap = (CTrap *) sceneObjects[a3_underHand->tagId];
                if (trap->typeData->objTypeId != 36 || (trap->triggerTrapsInRange_flags & 0x20) != 0) return;
                unsigned __int16 v33_direction = this->profiler->c_bridge->v_getCamera()->direction;
                __int16 v34_playerTagId = this->playerTagId;
                GameAction v42_act;
                v42_act.data1 = a3_underHand->tagId;
                v42_act.data2 = v33_direction;
                v42_act.data3 = 0;
                v42_act.actionKind = 64;
                v42_act._playerTagId = v34_playerTagId;
                v43_try = 7;
                this->pushAction(&v42_act);
            } break;
            default: return;
        }
        v43_try = -1;
        this->ingameCursor.sub_40ABC0(11, 0);
        return;
    }
    if (scheduleDropNextTick(this, a3_underHand)) return;
    if (!this->pCWorld->v_hasThingsInHand_5094B0(this->playerTagId)) return;
    int thingInHandIdx = this->pCWorld->v_getNumThingsInPlayerHand_5094D0(this->playerTagId) - 1;
    if(drop_thing_from_hand_fix::enabled) {
        CPlayer *player = (CPlayer *) this->pCWorld->v_getCTag_508C40(this->playerTagId);
        drop_thing_from_hand_fix::modifyCheckIdx(this, player, thingInHandIdx);
        if(thingInHandIdx < 0) return;
    }
    unsigned __int16 v36_thingInHandTagId;
    if (!this->pCWorld->v_getThingInPlayerHand_5094F0(this->playerTagId, thingInHandIdx, &v36_thingInHandTagId)) return;
    if (!this->pCWorld->v_fun_510000(a3_underHand->x, a3_underHand->y)) return;
    CThing *thingInHand = (CThing *) sceneObjects[v36_thingInHandTagId];

    if (!this->checkAllowToDrop(thingInHand, a3_underHand->x, a3_underHand->y)) return;
    if(drop_thing_from_hand_fix::enabled) {
        CPlayer *player = (CPlayer *) this->pCWorld->v_getCTag_508C40(this->playerTagId);
        drop_thing_from_hand_fix::onPushDropThing(player);
    }
    this->pushDropThingFromHandAction(thingInHand, a3_underHand);
}

typedef int (__thiscall *CPlayer_init_t)(dk2::CPlayer *_this, void *edx, dk2::PlayerList *a2);
int dk2::CPlayer::init(dk2::PlayerList *a2) {
    int ret = ((CPlayer_init_t) 0x004B8640)(this, NULL, a2);
    if(drop_thing_from_hand_fix::enabled) {
        drop_thing_from_hand_fix::init(this);
    }
    return ret;
}

typedef int (__fastcall *CPlayer_dropItemFromHand)(void *_this, void *edx, dk2::Vec3i *a2_pos, WORD *a3);
int dk2::CPlayer::dropThingFromHand(Vec3i *a2_pos, WORD *a3) {
    if(drop_thing_from_hand_fix::enabled) {
        drop_thing_from_hand_fix::commitThingDropped(this);
    }
    int ret = ((CPlayer_dropItemFromHand) 0x004BC710)(this, NULL, a2_pos, a3);
    return ret;
}

namespace dk2 {

    void dropThing(CDefaultPlayerInterface *self, CPI_ThingInHand *curThing) {
        if (curThing->dropped != 0) return;
        CThing *thingInHand = (CThing *) sceneObjects[curThing->tagId];
//        if(drop_thing_from_hand_fix::enabled) {
//            printf("ex drop [%d, %d] %d %s", curThing->underHand.x, curThing->underHand.y, thingInHand->f0_tagId, CThing_type_toString(thingInHand->fE_type));
//            if(thingInHand->fE_type == CThing_type_CObject) {
//                dk2::CObject *object = (dk2::CObject *) thingInHand;
//                printf(" obj.ty=%s", CObject_typeId_toString(object->typeId));
//            }
//            printf("\n");
//        }
        self->pushDropThingFromHandAction(thingInHand, &curThing->underHand);
        curThing->dropped = 1;
    }

}

void dk2::CDefaultPlayerInterface::tickThingsInHand() {
    CPlayer *v16_player = (CPlayer *) this->pCWorld->v_getCTag_508C40(this->playerTagId);
    if ( (v16_player->playerFlags & 0x80000) != 0 ) return;
    if ( !this->thingsInHand_count ) return;
    DWORD v17_timeMs = getTimeMs();
    unsigned int startIdx = 0;
    if ( !this->thingsInHand_count ) return;

    for (unsigned int i = 0; i < this->thingsInHand_count;) {
        CPI_ThingInHand *curThing = &this->thingsInHand[i];
        if ( sceneObjectsPresent[curThing->tagId] ) {
            int hasThingInHand = v16_player->hasThingInHand(curThing->tagId);
            if(hasThingInHand && curThing->hasUnderHand) {
                dropThing(this, curThing);
                ++i;
                startIdx = i;
                continue;
            }
            if (
                    !hasThingInHand &&
                    curThing->dropped != 1 &&
                    (v17_timeMs - curThing->timeMs) <= 2000
            ) {
                ++i;
                startIdx = i;
                continue;
            }
            CRenderInfo &renderInfo = ((CPhysicalThing *) sceneObjects[curThing->tagId])->renderInfo;
            renderInfo._flags2 = renderInfo._flags2 & 0xFE ^ 1;
        }
        if (i < this->thingsInHand_count ) {
            for (unsigned int j = i; j < this->thingsInHand_count; ++j) {
                this->thingsInHand[j] = this->thingsInHand[j + 1];
            }
            i = startIdx;
        }
        --this->thingsInHand_count;
    }
}
