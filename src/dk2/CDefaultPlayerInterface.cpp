//
// Created by DiaLight on 10.09.2024.
//
#include "dk2/CDefaultPlayerInterface.h"
#include "dk2/MyDblNamedSurface.h"
#include "dk2/entities/CCreature.h"
#include "dk2/entities/CDeadBody.h"
#include "dk2/entities/CObject.h"
#include "dk2/entities/CPlayer.h"
#include "dk2/entities/CTrap.h"
#include "dk2/entities/data/MyCreatureDataObj.h"
#include "dk2/entities/data/MyObjectDataObj.h"
#include "dk2/entities/data/MyTrapDataObj.h"
#include "dk2/network/MessageData.h"
#include "dk2/world/map/MyMapElement.h"
#include "dk2/sound/TbSysCommand_SetHandPosition.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "dk2_memory.h"
#include "gog_patch.h"
#include "patches/big_resolution_fix/expand_surf_idx_array.h"
#include "patches/micro_patches.h"
#include "tools/bug_hunter.h"
#include "patches/opengl/opengl_patch.h"
#include "tools/visual_debug.h"
#include "dk2/math/q12_utils.h"

#if __has_include(<dk2_research.h>)
   #include <dk2_research.h>
#endif


int dk2::CDefaultPlayerInterface::tickKeyboard2() {
    int v18_try_catch;

    Pos2i *MousePos = MyWindow_instance.getMousePos();
    int x = MousePos->x;
    int y = MousePos->y;
    int controlKeyFlags = MyInputManagerCb_static_buildControlFlags();
    int v15_isLControl = isActionKeyPressed(20, controlKeyFlags, 1);  // DIK_LCONTROL
    int v5_isLShift = isActionKeyPressed(21, controlKeyFlags, 1);  // DIK_LSHIFT
    int v13_isLShift = v5_isLShift;
    int ignoreModifiers = 0;
    if (v15_isLControl || v5_isLShift) ignoreModifiers = 1;
    int dwWidth = MyWindow_instance.dwWidth;
    int dwHeight = MyWindow_instance.dwHeight;

    if (!patch::control_windowed_mode::enabled) {
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
                v17_action.playerTagId = v7;
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
                v17_action.playerTagId = f8__cpyToF10;
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
    v17_action.playerTagId = this->playerTagId;
    v18_try_catch = 2;
    return this->pushAction(&v17_action);
}


void dk2::CDefaultPlayerInterface::createSurfacesForView_42CDF0(RtGuiView *view) {
    CBridge *pBridge = this->pGameSession->pBridge;
    char *rowPos = (char *) view->surf.lpSurface;
    int v4_bytesPerPix = view->dwRGBBitCount / 8;
    int v13_lineSize = 32 * view->surf.lPitch;
    char *v10__allyWindowText = (char *) view->surf.lpSurface;
    for (unsigned int _y = 0; _y < view->height_32blocks; ++_y) {
        char *linePos = rowPos;
        for (unsigned int _x = 0; _x < view->width_128blocks; ++_x) {
            int lPitch = view->surf.lPitch;
            Size2i v14_size;
            v14_size.w = 128;
            v14_size.h = 32;
            MySurface v15_surf;
            v15_surf.constructor(&v14_size, &view->surf.desc, linePos, lPitch);
            int _idx = _x + view->width_128blocks * _y;
            if (gog::RtGuiView_fix::isEnabled()) {
                if (_idx >= 93 && view == &dk2::CDefaultPlayerInterface_instance._allyWindowText) {
                    _idx = 0;
                }
            }
            int _id;
            if(patch::expand_surf_idx_array::enabled) {
                int *newArrp31x400_ids = (int *) view->Arrp31x400_ids[0];
                _id = newArrp31x400_ids[_idx];
            } else {
                _id = view->Arrp31x400_ids[_idx];
            }

            pBridge->v_f68_paintSurfToMapId(_id, &v15_surf, 1);
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

    if (patch::fix_chat_buffer_invalid_memory_access::enabled) {
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
    CBridge *pBridge = a4_dplif->pGameSession->pBridge;
    CCamera *a4_dplifa = pBridge->v_fD0_getCamera();
    if (a4_dplif->cgui_manager.f18) return 1;
    CCamera *v6_camera = pBridge->v_fD0_getCamera();
    BOOL result = v6_camera->isInputAllowed();
    if (!result) return result;
    if (a4_dplif->fFD
        || a4_dplifa->_mode != 7
           && a4_dplif->is3dEngineNe1
           && a4_dplifa->fun_44D620()
           && (a4_dplifa->_mode != 2 || a4_dplif->inMenu)
           && !a4_dplif->f10C
           && (a4_dplif->cgui_manager.fun_52C0A0(a3_coord, a1_KeyCode_F0toF3, a2_isPressed)
               || a4_dplif->sub_41FCF0(a3_coord.x, a3_coord.y, a1_KeyCode_F0toF3, a2_isPressed))
        || a4_dplif->pGameSession->inMenu) {
        return 1;
    }
    Pos2i v8_coord = a3_coord;
    a4_dplif->sub_40BFF0(&v8_coord, 0);
#if __has_include(<dk2_research.h>)
    research::onMouseAction(a4_dplif);
#endif
    if (a1_KeyCode_F0toF3 == 0xF0) {
        a4_dplif->handleLeftClick(a2_isPressed, &a4_dplif->_underHand);
    } else {
        if (a1_KeyCode_F0toF3 == 0xF1) {
            // underHand filled here 0040BFF0 -> 005992B0
            a4_dplif->handleRightClick(a2_isPressed, &a4_dplif->_underHand);
            return 1;
        }
        if (a1_KeyCode_F0toF3 == 0xF2 && a4_dplif->f10C) {
            a4_dplif->f10C = 0;
            return 1;
        }
    }
    return 1;
}

namespace dk2 {
    bool scheduleDropAfterTakingActionComplete(CDefaultPlayerInterface *self, ObjUnderHand *a3_underHand) {
        if (!self->thingsInHand_count) return false;
        CPI_ThingInHand *thingInHand = nullptr;
        for (int i = 0; i < self->thingsInHand_count; ++i) {
            CPI_ThingInHand *cur = &self->thingsInHand[i];
            if (cur->hasUnderHand) continue;
            thingInHand = cur;
            break;
        }
        if (thingInHand == nullptr) return false;
        if(patch::drop_thing_from_hand_fix::enabled) {
            if (!self->pCWorld->v_isCoordReachable_510000(a3_underHand->x8, a3_underHand->yC)) return true;
        }
        if (self->checkAllowToDrop((CThing *) sceneObjects[thingInHand->tagId], a3_underHand->x8, a3_underHand->yC)) {
            thingInHand->hasUnderHand = 1;
            static_assert(sizeof(ObjUnderHand) == 0x22);
            memcpy(&thingInHand->underHand, a3_underHand, sizeof(ObjUnderHand));
        }
        return true;
    }
}

void dk2::CDefaultPlayerInterface::handleRightClick(unsigned int a2_isPressed, ObjUnderHand *a3_underHand) {
    int v43_try;
    CBridge *pBridge = this->pGameSession->pBridge;
    this->pCWorld->v_getCTag_508C40(this->playerTagId);
    unsigned int cameraMode = pBridge->v_fCC_getCameraMode();
    if (cameraMode == 7) {
        this->cgui_manager.sub_52CCB0();
        if (a2_isPressed) {
            GameAction v38_act;
            v38_act.data1 = 3;
            v38_act.data2 = 0;
            v38_act.data3 = 0;
            v38_act.actionKind = 15;
            v38_act.playerTagId = this->playerTagId;
            v43_try = 0;
            this->pushAction(&v38_act);
            v43_try = -1;
            this->cgui_manager.pbtn_A0 = NULL;
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
        v38_act.playerTagId = this->playerTagId;
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
        v38_act.playerTagId = this->playerTagId;
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
                unsigned __int16 fD84_direction = this->pGameSession->pBridge->v_fD0_getCamera()->direction;
                GameAction v38_act;
                v38_act.data1 = a3_underHand->tagId;
                v38_act.data2 = fD84_direction;
                v38_act.data3 = 0;
                v38_act.actionKind = 62;  // SlapCreature
                v38_act.playerTagId = this->playerTagId;
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
                        unsigned __int16 v25_camDirection = this->pGameSession->pBridge->v_fD0_getCamera()->direction;
                        GameAction v39_act;
                        v39_act.data1 = a3_underHand->tagId;
                        v39_act.data2 = v25_camDirection;
                        v39_act.data3 = 0;
                        v39_act.actionKind = 62;  // SlapCreature
                        v39_act.playerTagId = this->playerTagId;
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
                    v40_act.playerTagId = v24_playerTagId;
                    v40_act.data1 = a3_underHand->tagId;
                    v40_act.data2 = (unsigned __int16) (f3F7_highPriorityBody & v29_playerMask) == 0;
                    v43_try = 5;
                    this->pushAction(&v40_act);
                }
            } return;
            case 4u: {  // CObject
                unsigned int f1C_type = ((CObject *) sceneObjects[a3_underHand->tagId])->typeObj->flags;
                if ((f1C_type & 0x200) == 0) return;
                unsigned __int16 v30_camDirection = this->pGameSession->pBridge->v_fD0_getCamera()->direction;
                GameAction v41_act;
                v41_act.data2 = v30_camDirection;
                v41_act.data1 = a3_underHand->tagId;
                v41_act.data3 = 0;
                v41_act.actionKind = 63;  // SlapObject
                v41_act.playerTagId = this->playerTagId;
                v43_try = 6;
                this->pushAction(&v41_act);
            } break;
            case 7u: {  // CTrap
                CTrap *trap = (CTrap *) sceneObjects[a3_underHand->tagId];
                if (trap->typeData->objTypeId != 36 || (trap->triggerTrapsInRange_flags & 0x20) != 0) return;
                unsigned __int16 v33_direction = this->pGameSession->pBridge->v_fD0_getCamera()->direction;
                __int16 v34_playerTagId = this->playerTagId;
                GameAction v42_act;
                v42_act.data1 = a3_underHand->tagId;
                v42_act.data2 = v33_direction;
                v42_act.data3 = 0;
                v42_act.actionKind = 64;
                v42_act.playerTagId = v34_playerTagId;
                v43_try = 7;
                this->pushAction(&v42_act);
            }
                break;
            default:
                return;
        }
        v43_try = -1;
        this->ingameCursor.sub_40ABC0(11, 0);
        return;
    }
    if (scheduleDropAfterTakingActionComplete(this, a3_underHand)) return;
    if (!this->pCWorld->v_hasThingsInHand_5094B0(this->playerTagId)) return;
    int thingInHandIdx = this->pCWorld->v_getNumThingsInPlayerHand_5094D0(this->playerTagId) - 1;
    uint16_t v36_thingInHandTagId;
    if (!this->pCWorld->v_getThingInPlayerHand_5094F0(this->playerTagId, thingInHandIdx, &v36_thingInHandTagId)) return;
    if (!this->pCWorld->v_isCoordReachable_510000(a3_underHand->x8, a3_underHand->yC)) return;
    CThing *thingInHand = (CThing *) sceneObjects[v36_thingInHandTagId];
    if (!this->checkAllowToDrop(thingInHand, a3_underHand->x8, a3_underHand->yC)) return;
    this->pushDropThingFromHandAction(thingInHand, a3_underHand);
}


namespace dk2 {
    bool checkPlayerAllowToDrop(CWorld *world, uint16_t playerTagId, CThing *thingInHand, int a4_x, int a5_y) {
        if (!thingInHand) return FALSE;
        if (thingInHand->fE_type == 0) {  // CCreature
            CCreature *creature = (CCreature *) thingInHand;
            MyMapElement *a5_ya = world->v_getMapElem(a4_x, a5_y);
            if (!world->v_sub_509310(a4_x, a5_y, playerTagId, creature->typeId)) {
                unsigned int stateFlags2 = creature->stateFlags2;
                return (stateFlags2 & 0x100) != 0 &&  // isTool
                       a5_ya->arr6DA4A8_idx == 35 &&
                       (stateFlags2 & 0x400) == 0;  // !hasBeenKnockedOut
            }
            MyMapElement *v9_mapElem = a5_ya;
            if (playerTagId != creature->f24_playerId) {
                if (a5_ya->sub_453A20(3) && a5_ya->fC == 4) return false;
            }
            int stateFlags2 = creature->stateFlags2;
            if ((stateFlags2 & 0x100) != 0 &&  // isTool
                (stateFlags2 & 0x400) == 0  // !hasBeenKnockedOut
                    ) {
                if ((v9_mapElem->_roomIdFFF & 0xFFF) == 0) return true;
                if (!v9_mapElem->sub_453A20(11)
                    && !v9_mapElem->sub_453A20(13)
                    && !v9_mapElem->sub_453A20(16)
                    || !v9_mapElem->sub_454110()) {
                    return !v9_mapElem->sub_453A20(12);
                }
                return false;
            }
            return true;
        }
        if (thingInHand->fE_type == 2)  // CObject
            return world->v_sub_509340(a4_x, a5_y, playerTagId, ((CObject *) thingInHand)->typeId);
        if (thingInHand->fE_type == 6)  // CDeadBody
            return world->v_sub_509370(a4_x, a5_y, playerTagId, ((CDeadBody *) thingInHand)->typeId);
        return true;
    }
}

BOOL dk2::CDefaultPlayerInterface::checkAllowToDrop(CThing *thingInHand, int a4_x, int a5_y) {
    return checkPlayerAllowToDrop(this->pCWorld, this->playerTagId, thingInHand, a4_x, a5_y);
}

int dk2::CPlayer::dropThingFromHand(Vec3i *a2_pos, uint16_t *a3_pDirection) {
    if (this->thingsInHand_count == 0) return 0;
    Vec3i *v5_pos = a2_pos;
    uint16_t v5_tagId = thingsInHand[this->thingsInHand_count - 1];
    CThing *v6_thing = (CThing *) sceneObjects[v5_tagId];
    this->thingsInHand_count--;
    v6_thing->fun_4B5560(v5_pos);
    int MapWhoType = v6_thing->getMapWhoType_except2();
    v6_thing->fun_4B4E70(MapWhoType);
    if (v6_thing->fE_type != 0 && v6_thing->fE_type != 2) return 1;

    if (v6_thing->fE_type == 0) {
        CCreature *creature = (CCreature *) v6_thing;
        MyMapElement *v10_mapElem = g_pCWorld->v_getMapElem_2(v5_pos);
        __int16 v11_mapElem = v10_mapElem->_playerIdFFF & 0xFFF;
        if (v11_mapElem != v6_thing->f24_playerId && v11_mapElem != this->f0_tagId) {
            if (v10_mapElem->sub_453A20(2))
                v6_thing->v_f24(v10_mapElem->_playerIdFFF & 0xFFF);
        }
        unsigned int f3E6_stateFlags = creature->stateFlags;
        creature->stateFlags = f3E6_stateFlags & ~1;
        creature->pickupTick = g_pWorld->getGameTick();
        creature->setCurrentState_48AD30(76);
        creature->lastPosition = *v5_pos;
        creature->pilotNavigation.calcPath_setPosVel_4D1070(creature);
        g_MySound_ptr->v_CSoundSystem_fun_5678F0(0, creature->creatureData->f6E3, 196, v5_pos);
        creature->sub_48CC90();
    } else if (v6_thing->fE_type == 2) {
        CObject *object = (CObject *) v6_thing;
        MyMapElement *v13_mapElem = g_pCWorld->v_getMapElem_2(v5_pos);
        MyMapElement *v14_mapelem = v13_mapElem;
        if ((v13_mapElem->_playerIdFFF & 0xFFF) != object->f24_playerId
            && object->typeId == 9
            && v13_mapElem->sub_453A20(4)) {
            object->v_f24(v14_mapelem->_playerIdFFF & 0xFFF);
        }
        object->fun_49EF60(1);
        int f10_underHandTagId = LOWORD(this->inst__playerAction.evData3);
        if (!sceneObjectsPresent[(unsigned __int16) f10_underHandTagId]) {
            if (object->typeId != 0 && object->typeId <= 3u) {
                uint16_t direction = 0;
                CEffect *v26_effect;
                g_pCWorld->v_sub_509580(32, (int) this->f0_tagId, v5_pos, &direction, &v26_effect);
                object->v_f24(g_neutralPlayerId);
            }
        } else {
            CCreature *v15_creature = (CCreature *) sceneObjects[f10_underHandTagId];
            if (v15_creature->fE_type == 0) {
                if (object->typeId) {
                    if (object->typeId <= 3u) {
                        MyCreatureDataObj *f370_creatureData = v15_creature->creatureData;
                        uint8_t level = v15_creature->level;
                        int v19_valByLevel = level == 1 ? f370_creatureData->f69A : f370_creatureData->f69A * g_pObj6F2550->field_129__money_byLevel[level] / 100;
                        if (v19_valByLevel) object->whoGetsThisFromADrop = v15_creature->f0_tagId;
                    } else if (object->typeId == 9) {  // Chicken
                        MyCreatureDataObj *v18_creatureData = v15_creature->creatureData;
                        uint8_t level = v15_creature->level;
                        int v19_valByLevel = level == 1 ? v18_creatureData->f66D : v18_creatureData->f66D * g_pObj6F2550->f171[level] / 100;
                        if (v19_valByLevel) object->whoGetsThisFromADrop = v15_creature->f0_tagId;
                    }
                }
            }
        }
        object->field_2A = g_MySound_ptr->v_CSoundSystem_fun_5678F0(
                object->field_2A,
                object->typeObj->f10E,
                196,
                &object->f16_pos);
    }
    CMovingThing *movingThing = (CMovingThing *) v6_thing;
    movingThing->fF0_direction = *a3_pDirection;
    movingThing->lastAngle = *a3_pDirection;
    return 1;
}


namespace dk2 {

    void dropThing(CDefaultPlayerInterface *self, CPI_ThingInHand *curThing) {
        if (curThing->dropped != 0) return;
        CThing *thingInHand = (CThing *) sceneObjects[curThing->tagId];
        self->pushDropThingFromHandAction(thingInHand, &curThing->underHand);
        curThing->dropped = 1;
    }

}

void dk2::CDefaultPlayerInterface::tickThingsInHand() {
    CPlayer *v16_player = (CPlayer *) this->pCWorld->v_getCTag_508C40(this->playerTagId);
    if ((v16_player->playerFlags & 0x80000) != 0) return;
    if (!this->thingsInHand_count) return;
    DWORD v17_timeMs = getTimeMs();
    unsigned int startIdx = 0;
    if (!this->thingsInHand_count) return;

    for (unsigned int i = 0; i < this->thingsInHand_count;) {
        CPI_ThingInHand *curThing = &this->thingsInHand[i];
        if (sceneObjectsPresent[curThing->tagId]) {
            int hasThingInHand = v16_player->hasThingInHand(curThing->tagId);
            if (hasThingInHand && curThing->hasUnderHand) {
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
        if (i < this->thingsInHand_count) {
            for (unsigned int j = i; j < this->thingsInHand_count; ++j) {
                this->thingsInHand[j] = this->thingsInHand[j + 1];
            }
            i = startIdx;
        }
        --this->thingsInHand_count;
    }
}

namespace dk2 {

    GameAction buildDropItemAction(CDefaultPlayerInterface *self, Q12 x_if12, Q12 y_if12, uint16_t tagId) {
        GameAction act;
        act.data1 = x_if12.value;  // x
        act.data2 = y_if12.value;  // y
        uint16_t v19_direction = self->pGameSession->pBridge->v_fD0_getCamera()->direction;
        act.data3 = tagId | (v19_direction << 16);
        act.actionKind = 61;  // DropItemFromHand
        act.playerTagId = self->playerTagId;
        return act;
    }

}

/**
 *
 * 0040E0D0 CDefaultPlayerInterface_tickThingsInHand
 *   CDefaultPlayerInterface_sub_40BBE0
 *     CDefaultPlayerInterface_sub_40BFF0
 *       CDefaultPlayerInterface_onMouseAction ->
 *         00402D00 CDefaultPlayerInterface__fun_402D00 ->
 *     004039A0 CDefaultPlayerInterface__fun_4039A0 ->
 *   004039A0 CDefaultPlayerInterface__fun_4039A0 ->
 * 00408EE0 CDefaultPlayerInterface_handleRightClick
 *   CDefaultPlayerInterface_onMouseAction ->
 *
 * CDefaultPlayerInterface_onMouseAction
 *   00402D00 CDefaultPlayerInterface__fun_402D00
 *     00526FF0 MyGameSession_attachPlayerI
 *       00525370 CGameComponent_mainGuiLoop
 *
 * 004039A0 CDefaultPlayerInterface__fun_4039A0
 *   00526590 MyGameSession_draw3dScene
 *     00525370 CGameComponent_mainGuiLoop
 */
void dk2::CDefaultPlayerInterface::pushDropThingFromHandAction(CThing *a2_thing, ObjUnderHand *a3_underHand) {
    int try_level;
    if (a2_thing->fE_type == 0) {  // CCreature
        GameAction act = buildDropItemAction(
                this, a3_underHand->x_if12, a3_underHand->y_if12, 0
        );
        // will go to 00513650 and then 004C0EE0
        try_level = 0;
        this->pushAction(&act);
        try_level = -1;
        this->f12DA.sub_40ABC0(8, 0);
        return;
    }
    if (a2_thing->fE_type == 2) {  // CObject
        int f1C_type = a3_underHand->type;
        switch (f1C_type) {
            case 2: {  // your CCreature
                GameAction act = buildDropItemAction(
                        this, a3_underHand->x_if12, a3_underHand->y_if12, a3_underHand->tagId
                );
                try_level = 1;
                this->pushAction(&act);
                try_level = -1;
                this->f12DA.sub_40ABC0(8, 0);
            }
                return;
            case 3: {  // others CCreature
                GameAction act = buildDropItemAction(
                        this, a3_underHand->x_if12, a3_underHand->y_if12, a3_underHand->tagId
                );
                try_level = 2;
                this->pushAction(&act);
                try_level = -1;
                this->f12DA.sub_40ABC0(8, 0);
            }
                return;
            case 4: {  // CObject
                GameAction act = buildDropItemAction(
                        this, a3_underHand->x_if12, a3_underHand->y_if12, a3_underHand->tagId
                );
                try_level = 3;
                this->pushAction(&act);
                try_level = -1;
                this->f12DA.sub_40ABC0(8, 0);
            }
                return;
            default: {
                GameAction act = buildDropItemAction(
                        this, a3_underHand->x_if12, a3_underHand->y_if12, 0
                );
                try_level = 4;
                this->pushAction(&act);
                try_level = -1;
                this->f12DA.sub_40ABC0(8, 0);
            }
                return;
        }
    }
    if (a2_thing->fE_type == 6) {
        GameAction act = buildDropItemAction(
                this, a3_underHand->x_if12, a3_underHand->y_if12, 0
        );
        try_level = 5;
        this->pushAction(&act);
        try_level = -1;
        this->f12DA.sub_40ABC0(8, 0);
        return;
    }

    GameAction act = buildDropItemAction(
            this, a3_underHand->x_if12, a3_underHand->y_if12, 0
    );
    try_level = 6;
    this->pushAction(&act);
    try_level = -1;
    this->f12DA.sub_40ABC0(8, 0);
}

int dk2::CDefaultPlayerInterface::sub_42C7D0(int a2_width, int a3_height, int a4, const char *a5_name, RtGuiView *rtGuiView) {
    if(patch::expand_surf_idx_array::enabled) {
        patch::expand_surf_idx_array::allocate(rtGuiView);
    }
    MySurfDesc v21_desc = MyCEngineSurfDesc_bgra32_instance.desc;

    rtGuiView->height = a3_height;
    unsigned int v8_height_32blocks = (unsigned int)(a3_height + 31) >> 5;
    rtGuiView->height_32blocks = v8_height_32blocks;
    v8_height_32blocks *= 32;
    rtGuiView->height_32align = v8_height_32blocks;

    rtGuiView->width = a2_width;
    unsigned int v9_width_128blocks = (unsigned int)(a2_width + 127) >> 7;
    rtGuiView->width_128blocks = v9_width_128blocks;
    v9_width_128blocks <<= 7;
    rtGuiView->width_128align = v9_width_128blocks;

    unsigned int dwRGBBitCount = v21_desc.dwRGBBitCount;
    rtGuiView->dwRGBBitCount = dwRGBBitCount;
    size_t v19_blocksCount_bytes = v9_width_128blocks * v8_height_32blocks * (dwRGBBitCount >> 3);
    rtGuiView->blocksCount_bytes = v19_blocksCount_bytes;
    rtGuiView->blocksBuf = dk2::operator_new(v19_blocksCount_bytes);
    if (!rtGuiView->blocksBuf) return 0;
    
    CBridge *pBridge = this->pGameSession->pBridge;
    for (unsigned int _y = 0; _y < rtGuiView->height_32blocks; ++_y) {
        for (unsigned int _x = 0; _x < rtGuiView->width_128blocks; ++_x) {
            sprintf(g_temp_string, "%s Page%d_%d", a5_name, _x, _y);
            int* pInt;
            if(patch::expand_surf_idx_array::enabled) {
                pInt = patch::expand_surf_idx_array::getPIdx(rtGuiView, _x, _y);
            } else {
                pInt = &rtGuiView->Arrp31x400_ids[_x + rtGuiView->width_128blocks * _y];
            }
            if (!pBridge->v_createMyScaledSurface(g_temp_string, 128, 32, 257, pInt)) {
                dk2::operator_delete(rtGuiView->blocksBuf);
                rtGuiView->blocksBuf = NULL;
                return FALSE;
            }
        }
    }
    int v14_lPitch = rtGuiView->width_128align * (rtGuiView->dwRGBBitCount >> 3);
    Size2i v20_size {rtGuiView->width, rtGuiView->height};
    MySurface v20_size_surf;
    v20_size_surf.constructor(&v20_size, &v21_desc, rtGuiView->blocksBuf, v14_lPitch);
    rtGuiView->surf = v20_size_surf;
    rtGuiView->f297 = 1;
    return TRUE;
}

void dk2::CDefaultPlayerInterface::sub_42CEE0(RtGuiView *view, int a3_x, int a4_y, int a5) {
    CBridge *pBridge = this->pGameSession->pBridge;
    CWorldEntry v19_worldEntry;
    v19_worldEntry.constructor();
    char v21_renderInfo_buf[sizeof(CRenderInfo)];
    CRenderInfo &v21_renderInfo = *(CRenderInfo *) v21_renderInfo_buf;
    v21_renderInfo.constructor();
    int v22_tryLevel = 0;
    MyRenderInit_Sprite v18_init;
    v18_init.typeA = 2;
    unsigned int v17_v4096 = 4096;
    v18_init.randRange = 0;
    v18_init.weB_flags = 0;
    for(unsigned int blockY = 0; blockY < view->height_32blocks; ++blockY) {
        int _y = a4_y + blockY * 32;
        for (unsigned int blockX = 0; blockX < view->width_128blocks; ++blockX){
            int _x = a3_x + blockX * 128;
            unsigned int v10_v4096 = v17_v4096;
            int v14 = 1;
            int v13 = 0;
            unsigned int idx = blockX + view->width_128blocks * blockY;
            int _id;
            if(patch::expand_surf_idx_array::enabled) {
                int *newArrp31x400_ids = (int *) view->Arrp31x400_ids[0];
                _id = newArrp31x400_ids[idx];
            } else {
                _id = view->Arrp31x400_ids[idx];
            }
            v19_worldEntry.idx = _id;
            v19_worldEntry._height.value = v17_v4096;
            v19_worldEntry._width.value = 4096;
            int v12_v4096 = v10_v4096 | HIBYTE(v18_init.weB_flags);
            int *p_v12_v4096 = &v12_v4096;
            *(DWORD *)&v19_worldEntry.u.randRange = *(DWORD *)&v18_init.randRange;
            v19_worldEntry.u.weB_flags = 1;
//            __setValue(&v12_v4096, 0);
            v12_v4096 = 0;
            v21_renderInfo.fun_4B37D0(&v19_worldEntry, v12_v4096, v13, v14);
            v21_renderInfo._widthScale = 128;
            v21_renderInfo._heightScale = 32;
            v21_renderInfo.f14 = 0;
            v21_renderInfo.f18 = 0;
            v21_renderInfo.r48 = -1;
            v21_renderInfo.g49 = -1;
            v21_renderInfo.b4A = -1;
            v21_renderInfo.f4B = -1;
            pBridge->v_f5C_create2DMeshAt(_x, _y, a5, &v21_renderInfo);
        }
    }
    v22_tryLevel = -1;
    v21_renderInfo.destructor();
}

void __cdecl dk2::CDefaultPlayerInterface_WM_ACTIVATE_cb(int activated, int a2, int a3, int a4_ctx) {
    int status;
    auto *plif = (CDefaultPlayerInterface *) a4_ctx;
    if (activated == 2) {
        plif->sub_40CA70();
        for (int i = 21; i >= 0; --i) {
            MyDdSurfaceEx *v4 = &g_roomIcons_surfs[i];
            if (MyDdSurface_addRef(&v4->dd_surf, 0))
                MyDdSurface_release(&status, &v4->dd_surf);
        }
        for (int i = 20; i >= 0; --i) {
            MyDdSurfaceEx *v6 = &g_creatureIcons_surfs[i];
            if (MyDdSurface_addRef(&v6->dd_surf, 0))
                MyDdSurface_release(&status, &v6->dd_surf);
        }
        for (int i = 12; i >= 0; --i) {
            MyDdSurfaceEx *v8 = &g_trapIcons_surfs[i];
            if (MyDdSurface_addRef(&v8->dd_surf, 0))
                MyDdSurface_release(&status, &v8->dd_surf);
        }
        for (int i = 6; i >= 0; --i) {
            MyDdSurfaceEx *v10 = &g_doorIcons_surfs[i];
            if (MyDdSurface_addRef(&v10->dd_surf, 0))
                MyDdSurface_release(&status, &v10->dd_surf);
        }
        if (MyDdSurface_addRef(&g_GameMapBackground_surf.dd_surf, 0))
            MyDdSurface_release(&status, &g_GameMapBackground_surf.dd_surf);
        if (MyDdSurface_addRef(&g_GameMapBackgroundRock_surf.dd_surf, 0))
            MyDdSurface_release(&status, &g_GameMapBackgroundRock_surf.dd_surf);
        if (MyDdSurface_addRef(&g_GameMapForeground_surf.dd_surf, 0))
            MyDdSurface_release(&status, &g_GameMapForeground_surf.dd_surf);
    } else if (activated == 3) {
        plif->sub_40AC40();
        g_isSomthingReady_006CE008 = 1;
        
        if (patch::opengl_patch::enabled) {
            patch::opengl_patch::createOglTexture(g_GameMapForeground_surf, 256, 256, false);
        } else {
            if (*MyDdSurface_createOffScreenSurface(
                    &status, 256u, 256u, DDSCAPS_SYSTEMMEMORY, &g_GameMapForeground_surf.dd_surf) < 0) return;
        }
        
        char dbns_buf[sizeof(MyDblNamedSurface)];
        MyDblNamedSurface &dbns = *(MyDblNamedSurface *) dbns_buf;
        dbns.constructor("MapOverlay", "MapOver", 2, 0, 1);
        g_idx = MyEntryBuf_MyScaledSurface_create(&dbns, 1);
        FSMAP_load_403060();
    }
}

namespace dk2 {

    void my_png_destroy(void **self) {
        if (*self)
            libpng_png_destroy_info_struct(0, self);
    }

}

int dk2::CDefaultPlayerInterface::sub_40C710() {
    int status;
    CBridge *f10_pBridge = this->pGameSession->pBridge;

    char pngLoader_buf[sizeof(TbPNGLoader)];
    TbPNGLoader &pngLoader = *(TbPNGLoader *) pngLoader_buf;
    pngLoader.surf.constructor_empty();
    *(void **) &pngLoader = TbPNGLoader::vftable;
    pngLoader.s_png_infopp = 0;
    pngLoader.s_png_structpp = 0;
    int try_level = 0;
    for (int i = 0; i < 16; ++i) {
        StubStruc68F650 *pCursor = &g_interfaceCursorArr[i];
        if (!pCursor->name) {
            pCursor->cursorSurf = NULL;
            continue;
        }
        MyDdSurfaceEx a2_cursors;
        a2_cursors.dd_surf.fld10_00 = 0;
        a2_cursors.dd_surf.fld11_ff = 0;
        a2_cursors.dd_surf.fld12_00 = 0;
        a2_cursors.dd_surf.fld13_ff = 0;
        a2_cursors.dd_surf.dwColorSpaceValue_00 = 0;
        a2_cursors.dd_surf.f20 = 0;
        a2_cursors.dd_surf.dd_surface = 0;
        a2_cursors.surf.constructor_empty();
        unsigned __int16 v2 = MyResources_instance.gameCfg.fun_55D540();
        if (*loadArtToSurfaceEx(&status, &a2_cursors, &MyResources_instance.spriteFileMan, pCursor->name, v2) < 0) {
            try_level = 1;
            my_png_destroy(&pngLoader.s_png_infopp);
            return -1;
        }
        {
            MyDdSurfaceEx *pSurf = (MyDdSurfaceEx *) dk2::operator_new(sizeof(MyDdSurfaceEx));
            try_level = 2;
            if (pSurf) {
                pSurf->dd_surf.fld10_00 = 0;
                pSurf->dd_surf.fld11_ff = 0;
                pSurf->dd_surf.fld12_00 = 0;
                pSurf->dd_surf.fld13_ff = 0;
                pSurf->dd_surf.dwColorSpaceValue_00 = 0;
                pSurf->dd_surf.f20 = 0;
                pSurf->dd_surf.dd_surface = 0;
                pSurf->surf.constructor_empty();
            } else {
                pSurf = 0;
            }
            pCursor->cursorSurf = pSurf;
        }

        if (patch::opengl_patch::noSoftwareScale) {
            pCursor->size = pCursor->imgSize;
            pCursor->pointerOffs = pCursor->imgPointerOffs;
        } else {
            unsigned int dwWidth = MyWindow_instance.dwWidth;
            unsigned int dwHeight = MyWindow_instance.dwHeight;
            pCursor->size.w = dwWidth * pCursor->imgSize.w / 640;
            pCursor->size.h = dwHeight * pCursor->imgSize.h / 480;

            pCursor->pointerOffs.x = dwWidth * pCursor->imgPointerOffs.x / 640;
            pCursor->pointerOffs.y = dwHeight * pCursor->imgPointerOffs.y / 480;
        }

        bool surfCreated;

        try_level = 0;
        if (patch::opengl_patch::enabled) {
            patch::opengl_patch::createOglTexture(*pCursor->cursorSurf, pCursor->size.w, pCursor->size.h * pCursor->f4, false);
            surfCreated = true;
        } else {
            MyDdSurface_createOffScreenSurface(&status, pCursor->size.w, pCursor->size.h * pCursor->f4, DDSCAPS_SYSTEMMEMORY, &pCursor->cursorSurf->dd_surf);
            surfCreated = status >= 0;
        }
        if (surfCreated) {
            static_MyDdSurfaceEx_Blt(&status, pCursor->cursorSurf, NULL, &a2_cursors, NULL, 0);
            {  // probably set alpha color
                int p_f10_fld10_00 = (int) &pCursor->cursorSurf->dd_surf.fld10_00;
                *(DWORD *) p_f10_fld10_00 = 0xFF00FF00;
                *(BYTE *) (p_f10_fld10_00 + 4) = 0;
            }
            MyDdSurface_release(&status, &a2_cursors.dd_surf);
        } else {
            dk2::operator_delete(pCursor->cursorSurf);
            pCursor->cursorSurf = NULL;
        }
    }
    CWorldEntry *v9 = (CWorldEntry *) dk2::operator_new(13 * sizeof(CWorldEntry));
    static_assert(13 * sizeof(CWorldEntry) == 0x15F);
    CWorldEntry *v10 = v9;
    CWorldEntry *v18 = v9;
    try_level = 3;
    if (v9) {
        CWorldEntry *v11 = v9;
        int v12 = 13;
        do {
            v11->constructor();
            v11++;
            --v12;
        } while (v12);
    } else {
        v10 = 0;
    }
    try_level = 0;
    g_pCWorldEntry = v10;
    if (!v10) {
        try_level = 5;
        my_png_destroy(&pngLoader.s_png_infopp);
        return 0;
    }
    for (int i = 0; i < 13; ++i) {
        char **v14 = &g_cursorNames[i];
        int v19;
        if (!f10_pBridge->v_f54_allocateRenderObj(*v14, 2, 0, &v19, 1, 0)) {
            try_level = 4;
            my_png_destroy(&pngLoader.s_png_infopp);
            return 0;
        }
        CWorldEntry *v15 = g_pCWorldEntry;
        g_pCWorldEntry[i].idx = v19;
        CWorldEntry *v16 = &v15[i];
        v16->_width.value = 4096;
        v16->_height.value = 4096;
        *(DWORD *) &v16->u.randRange = 0x10000;
        *(WORD *) ((char *) &v16->u.weB_flags + 1) = 0;
        ((uint8_t *) &v16->u.weB_flags)[3] = 0; // HIBYTE(v16->u.weB_flags) = 0;
        v16->u.weB_flags |= v16->u.typeA != 0;
    }
    try_level = 6;
    my_png_destroy(&pngLoader.s_png_infopp);
    return 1;
}


void dk2::CDefaultPlayerInterface::sub_40ACD0() {
    int status;
    CEngineInterface *f10_pBridge = this->pGameSession->pBridge;
    CPlayer *pPlayer = (CPlayer *) this->pCWorld->v_getCTag_508C40(this->playerTagId);
    if (pPlayer->status
        && MyResources_instance.gameCfg.useFe_playMode != 4
        && (MyResources_instance.gameCfg.useFe_playMode != 3 || (pPlayer->playerFlags & 0x80000) != 0)) {
        Pos2i v15 {0, 0};
        static_MyInputManagerCb_setCursorIconAndDraw(&status, 0, 0, &v15);
        return;
    }
    this->f12DA.fun_40AAE0();
    this->f12F6.fun_40AAE0();
    this->ingameCursor.fun_40AAE0();
    f10_pBridge->sub_44E130(&this->aabb132F, this->tagId10BC);
    f10_pBridge->sub_44E1C0(&this->aabb132F, this->tagId10BC);
    f10_pBridge->f32__allowToDrop = (this->cursorFlags >> 4) & 1;
    int f0_currentCursorIdx;
    int cursorFrameIdx;
    if (this->ingameCursor.currentCursorIdx) {
        cursorFrameIdx = this->ingameCursor.cursorFrameIdx;
        f0_currentCursorIdx = this->ingameCursor.currentCursorIdx;
    } else {
        f0_currentCursorIdx = this->f12F6.currentCursorIdx;
        if (f0_currentCursorIdx) {
            cursorFrameIdx = this->f12F6.cursorFrameIdx;
        } else {
            f0_currentCursorIdx = this->f12DA.currentCursorIdx;
            cursorFrameIdx = this->f12DA.cursorFrameIdx;
        }
    }
    Size2i &cursorSize = g_interfaceCursorArr[f0_currentCursorIdx].size;
    AABB surfAabb {
            0, cursorSize.h * cursorFrameIdx,
            cursorSize.w, cursorSize.h + cursorSize.h * cursorFrameIdx
    };
    if (!this->f3B94) return;
    CCamera *pCamera = f10_pBridge->v_fD0_getCamera();
    if ((this->cursorFlags & 1) == 0 && pCamera->fun_44D620()) {
        Pos2i pointerOffs = g_interfaceCursorArr[f0_currentCursorIdx].pointerOffs;
        static_MyInputManagerCb_setCursorIconAndDraw(&status, g_interfaceCursorArr[f0_currentCursorIdx].cursorSurf, &surfAabb, &pointerOffs);
        return;
    }
    Pos2i v15 {0, 0};
    static_MyInputManagerCb_setCursorIconAndDraw(&status, 0, 0, &v15);
}

int dk2::CDefaultPlayerInterface::fun_4039A0(int a4) {
    int try_level;
    if (!a4) return 1;
    MyGameSession *f4_pGameSession = this->pGameSession;
    this->pCWorld = f4_pGameSession->pWorld;
    CBridge *pBridge = f4_pGameSession->pBridge;
    CPlayer *pPlayer = (CPlayer *) f4_pGameSession->pWorld->v_getCTag_508C40(this->playerTagId);
    CCamera *v8_camera = pBridge->v_fD0_getCamera();
    int cameraMode = pBridge->v_fCC_getCameraMode();
    if (cameraMode == 18) {
        this->f105 = 0;
    } else {
        this->fFD = 0;
        this->f101 = 0;
        this->f105 = 1;
    }
    if (pPlayer->status) {
        if ((pPlayer->playerFlags & 0x400000) == 0) {
            this->f101 = 1;
            this->fFD = 1;
            this->is3dEngineNe1 = 0;
            this->f105 = 0;
            this->cursorFlags = this->cursorFlags | 1;
            if (pPlayer->status != 2) {
                if (MyResources_instance.gameCfg.useFe_playMode != 3 && v8_camera->_mode != 18) {
                    GameAction action;
                    memset(&action, 0, 12);
                    action.actionKind = 1;
                    action.playerTagId = this->playerTagId;
                    try_level = 0;
                    this->pushAction(&action);
                    try_level = -1;
                }
            }
        }
    }
    if (this->flags13DA && (pPlayer->playerFlags & 0x400000) != 0) {
        this->cursorFlags &= ~1u;
        this->fFD = 0;
        this->f101 = 0;
        this->f105 = 1;
        this->is3dEngineNe1 = 1;
        this->flags13DA = 0;
    }
    if (pPlayer->status == 2 && MyResources_instance.gameCfg.useFe_playMode == 4) {
        this->f101 = 0;
        this->fFD = 0;
        this->cursorFlags = this->cursorFlags & 0xFE;
        this->is3dEngineNe1 = 1;
        this->f105 = 1;
        GameAction action;
        action.data1 = 2;
        action.data2 = 0;
        action.data3 = 0;
        action.actionKind = 116;
        action.playerTagId = this->playerTagId;
        try_level = 1;
        this->pushAction(&action);
        try_level = -1;
        this->cgui_manager.findGameWindowById(51)->f44_isCurrent = 1;
    }
    if (cameraMode == 2) {
        if (sceneObjectsPresent[pPlayer->creaturePossessed]) {
            CCreature *pCreature = (CCreature *) sceneObjects[pPlayer->creaturePossessed];
            if (!pCreature->fE_type) {
                int f4_gameTick = this->pGameSession->gameTick;
                if (this->f10B4 != f4_gameTick) {
                    this->f10B4 = f4_gameTick;
                    GameAction action;
                    action.data1 = (v8_camera->location.x + v8_camera->locationOffset.x).value;
                    action.data2 = (v8_camera->location.y + v8_camera->locationOffset.y).value;
                    action.data3 = (pCreature->creatureData->f65C & 0xFFFF) | ((v8_camera->direction & 0xFFFF) << 16);
                    action.actionKind = 25;
                    action.playerTagId = this->playerTagId;
                    try_level = 2;
                    this->pushAction(&action);
                    try_level = -1;
                }
            }
        }
    }
    if (v8_camera->sub_44D5E0()) {
        switch (this->_someTy) {
            case 1:
                this->_someTy = 0;
                this->f12F6.sub_40ABC0(0, 0);
                this->f10C = 0;
                this->f13E4 = 0;
                break;
            case 3:
                this->f13F0 = 0;
                break;
            case 4:
                this->f13F0 = 0;
                break;
        }
    }
    if (this->f4F25 <= getTimeMs()) {
        if (this->f4F2D == 1) {
            this->sub_40FA90();
        } else if (this->f4F2D == 2) {
            this->sub_40FDA0();
        }
        this->f4F25 = 0;
        this->f4F2D = 0;
    }
    this->updateGameCounters();
    this->tickedCount_4039A0 = 0;
    do {
        Pos2i pos2i = *MyWindow_instance.getMousePos();
        if (cameraMode == 7) {
            this->f12B2 = 1;
        } else if (this->is3dEngineNe1) {
            this->f12B2 = this->cgui_manager.probably_isCursorAtButton() || this->sub_41FDF0(pos2i.x, pos2i.y);
        } else {
            this->f12B2 = 0;
        }
        this->sub_40BFF0(&pos2i, 1);
        if (!this->tickedCount_4039A0 || (unknown_libname_42() && this->tickedCount_4039A0 < 3u)) {
            if (this->cgui_manager.sub_52C520()) {
                MyInputManagerCb_static_processInputs_setStaticListenersAndHandleDxActions(&this->field_133F_static_listeners, 0, (CComponent *) this, 0);
            } else {
                MyInputManagerCb_static_processInputs_setStaticListenersAndHandleDxActions(&this->field_133F_static_listeners, 1, (CComponent *) this, 0);
            }
        }
        CCamera *v24 = v8_camera;
        if ((CCamera_mode_sub_44D870(cameraMode) == 2 ||
             this->pGameSession->inMenu && CCamera_mode_sub_44D870(cameraMode) == 1)
            && (this->is3dEngineNe1 && v24->fun_44D620() || (pPlayer->playerFlags & 0x80000) != 0)) {
            this->sub_407260();
        }
        if (!this->cgui_manager.sub_52C520())
            this->tickKeyboard(&this->_underHand);
        this->tickThingsInHand();
        this->sub_40ACD0();
        this->sub_407380();
        this->timeMs = getTimeMs();
        this->tickedCount_4039A0 += 1;
    } while (this->tickedCount_4039A0 < 3u);
    if (this->doLoadSave) {
        this->pCWorld->v_f2C_loadFromFile(this->saveFilePath);
        g_MySound_ptr->v_fun_567810(0, g_soundNameList[25].f24, 833);
    }
    CWindow *pCWindow = this->cgui_manager.findGameWindowById(52);
    int status;
    if (this->cgui_manager.sub_52C520()) {
        if (!this->usingIme) {
            MyInputMethodEditor_instance1.replaceWndProc(&status, getHWindow());
            this->usingIme = status == 0;
        }
        CWindow_sub_428360_Unk52(pCWindow, this);
    } else {
        if (this->usingIme == 1)
            MyInputMethodEditor_instance1.restoreWndProc();
        this->usingIme = 0;
    }
    CWindow_sub_428360_Unk52(pCWindow, this);
    CCamera *pCamera = pBridge->v_fD0_getCamera();
    {
        GameAction soundCmd;
        *(void **) &soundCmd.data1 = TbSysCommand_SetHandPosition::vftable;
        *(uint32_t *) &soundCmd.data2 = (pCamera->location.x + pCamera->locationOffset.x - this->_underHand.x_if12).value;
        *(uint32_t *) &soundCmd.data3 = (pCamera->location.y + pCamera->locationOffset.y - this->_underHand.y_if12).value;
        soundCmd.actionKind = 0;
        g_MySound_ptr->v_fun_567A40(&status, &soundCmd);
    }
    return 1;
}

