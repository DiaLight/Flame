//
// Created by DiaLight on 19.10.2024.
//
#include <dk2/CWorld.h>
#include <dk2/entities/CPlayer.h>
#include <dk2/entities/CActionPoint.h>
#include <dk2/entities/CCreature.h>
#include <dk2/entities/data/MyCreatureDataObj.h>
#include <dk2/world/map/MyMapElement.h>
#include <dk2/world/nav/MyNavigationSystem.h>
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "patches/micro_patches.h"


namespace dk2 {

    void finalizeSpawnParty(CWorld *self, CPlayer *v57_player, uint8_t a2_heroPartyIdx, int v55_bool) {
        unsigned __int16 f0_tagId = 0;
        unsigned __int8 v46_positionInParty = 0;
        CCreature *v68_leaderCreature = nullptr;
        unsigned int v47_movementSpeed = 0x7FFFFFFF;
        ++self->invasionPartyCountArr[a2_heroPartyIdx];
        for (CCreature *j = (CCreature *) sceneObjects[v57_player->ownedCreature_first]; j; j = (CCreature *) sceneObjects[j->fC_playerNodeY]) {
            if (j->partyId != a2_heroPartyIdx) continue;
            if (v47_movementSpeed > j->creatureData->speed_0)
                v47_movementSpeed = j->creatureData->speed_0;
            if ((j->flags & 2) != 0) {  // LEADER
                f0_tagId = j->f0_tagId;
                v68_leaderCreature = j;
            }
        }
        if (v55_bool) {
            CCreature *v49_creature = (CCreature *) sceneObjects[f0_tagId];
            Vec3i v65_pos;
            v65_pos.x = v49_creature->f16_pos.x;
            v65_pos.y = v49_creature->f16_pos.y;
            v65_pos.z = 0x2000;
            uint16_t v71_direction = 0;
            CEffect *effect;
            self->v_sub_509580(
                    43,
                    v49_creature->f24_playerId,
                    &v65_pos,
                    &v71_direction,
                    &effect);
        }
        for (CCreature *i = (CCreature *) sceneObjects[v57_player->ownedCreature_first]; i; i = (CCreature *) sceneObjects[i->fC_playerNodeY]) {
            if (i->partyId != a2_heroPartyIdx) continue;
            i->setMovementSpeed(0, v47_movementSpeed);
            if ((i->flags & 4) != 0) {  // FOLLOWER
                i->myLeadersId = f0_tagId;
                i->positionInParty = ++v46_positionInParty;
            }
        }
        if(hero_party_spawn_limit_fix::enabled) if(v68_leaderCreature == nullptr) return;
        v68_leaderCreature->positionInParty = v46_positionInParty;
    }

    Vec3i findActionPointCenter(CWorld *self, int a3_actionPointId) {
        unsigned __int16 fA_firstActionPointId = self->creatures.firstActionPointId;
        for (CActionPoint *i = (CActionPoint *) sceneObjects[fA_firstActionPointId]; i;
                i = (CActionPoint *) sceneObjects[i->f4_typeNodeY]) {
            if(i->id != (BYTE) a3_actionPointId) continue;
            uint16_t startY = i->start.y;
            uint16_t endY = i->end.y;
            uint16_t startX = i->start.x;
            uint16_t endX = i->end.x;
            Vec3i v65_vecCenter;
            v65_vecCenter.z = 0;
            v65_vecCenter.x = ((startX + endX) / 2) << 12;
            v65_vecCenter.y = ((startY + endY) / 2) << 12;
            return v65_vecCenter;
        }
        Vec3i v65_vecCenter;
        memset(&v65_vecCenter, 0, sizeof(v65_vecCenter));
        return v65_vecCenter;
    }
    MyCreatureDataObj *findCreatureDataObjForParty(
            CWorld *self, bool a4_bool, unsigned int v23_goodIdx,
            int v59_creatureDataArrCount, GoodCreature &v68_goodCr,
            BYTE &f1C_creatureTypeId) {
        if (!a4_bool) {
            f1C_creatureTypeId = v68_goodCr.creatureTypeId;
            return self->v_fun_50D390(v68_goodCr.creatureTypeId);
        }
        if (!v23_goodIdx) {
            f1C_creatureTypeId = 14;  // Dwarf
            return self->v_fun_50D390(14u);
        }
        while(true) {
            char v27_randomType = randomInt(
                    v59_creatureDataArrCount,
                    &self->gameSeed,
                    (char *) R"(D:\Dev\DK2\Projects\Source\Game\WorldTrigger.cpp)",
                    1586
            );
            f1C_creatureTypeId = v27_randomType + 1;
            MyCreatureDataObj *v30_creatureDataObj = self->v_fun_50D390(f1C_creatureTypeId);
            if(!v30_creatureDataObj) continue;
            if((v30_creatureDataObj->flags & 0x40000000) == 0) continue;
            return v30_creatureDataObj;
        }
    }

    int spawnWholeParty(CWorld *self, uint8_t a2_heroPartyIdx, int a3_actionPointId, bool a4_bool) {
        int v55_bool = 0;
        Vec3i v65_vecCenter = findActionPointCenter(self, (BYTE) a3_actionPointId);
        MyMapElement *v12_mapelem = self->v_getMapElem_2(&v65_vecCenter);
        unsigned __int8 fA_arr6DA4A8_idx = v12_mapelem->arr6DA4A8_idx;
        if (fA_arr6DA4A8_idx == 33) {
            v65_vecCenter.y += 4096;
            v65_vecCenter.x += 4096;
            uint16_t direction = 0;
            CEffect *v61_effect;
            self->v_sub_509580(311, g_goodPlayerId, &v65_vecCenter, &direction, &v61_effect);
        } else if (fA_arr6DA4A8_idx != 37) {
            v55_bool = 1;
        }
        for (CCreature *i_creature = (CCreature *) sceneObjects[v12_mapelem->sceneObjIdx];
             i_creature;
             i_creature = (CCreature *) sceneObjects[i_creature->f8_mapWhoNodeY]) {
            int fE_type = i_creature->fE_type;
            if (fE_type == 4 || fE_type == 3) {
                i_creature->v_f20_setHealth0();
                uint16_t direction = 0;
                CEffect *v61_effect;
                self->v_sub_509580(1, i_creature->f24_playerId, &v65_vecCenter, &direction, &v61_effect);
            }
        }

        __int16 v21_triggerId = self->_heroPartyArr[a2_heroPartyIdx].triggerId;
        if (v21_triggerId) self->_set_trigger_flag_sub_519A20(v21_triggerId, 1);
        int v22_creatureDataArrCount = self->v_loc_508E50();
        unsigned int v23_goodIdx = 0;
        CPlayer *v57_player = self->playerList.players_7;
        while (true) {
            GoodCreature v68_goodCr = self->_heroPartyArr[a2_heroPartyIdx].goodCreatures[v23_goodIdx];
            if (v68_goodCr.creatureTypeId) {
                BYTE v54_creatureTypeId;
                MyCreatureDataObj *v30_creatureDataObj = findCreatureDataObjForParty(
                        self, a4_bool, v23_goodIdx, v22_creatureDataArrCount, v68_goodCr,
                        v54_creatureTypeId);
                CCreature *v53_creature;
                if (!self->WorldTrigger_spawnCreatureByTrigger(
                        v57_player->f0_tagId,
                        v54_creatureTypeId,
                        &v65_vecCenter,
                        &v53_creature)) {
                    if(hero_party_spawn_limit_fix::enabled) {
                        finalizeSpawnParty(self, v57_player, a2_heroPartyIdx, v55_bool);
                        return 1;
                    }
                    return 0;
                }
                if (v54_creatureTypeId == 21) {  // King
                    for (CPlayer *j_player = (CPlayer *) sceneObjects[self->playerList.allocatedList];
                         j_player;
                         j_player = (CPlayer *) sceneObjects[j_player->nextIdx]) {
                        self->playerMessageQueue.fun_4C4600(5, j_player->f0_tagId, 1, v53_creature->f0_tagId, 1);
                    }
                }
                unsigned __int8 fE_level = v68_goodCr.level;
                BYTE v69_count = v68_goodCr.level - 1;
                if (a4_bool) {
                    unsigned __int8 InvasionPartyCount = self->getInvasionPartyCount(a2_heroPartyIdx);
                    v69_count = InvasionPartyCount + v69_count;
                }
                v69_count %= 10;

                unsigned int v36_maxGoldHeld;
                if (fE_level == 1) {
                    v36_maxGoldHeld = v30_creatureDataObj->_maxGoldHeld;
                } else {
                    v36_maxGoldHeld = v30_creatureDataObj->_maxGoldHeld
                                      * g_pObj6F2550->_maxGoldHeldMultiplier_byLevel[fE_level]
                                      / 100;
                }
                v53_creature->fun_48AE70((__int64) ((double) v68_goodCr.goldHeldPercent * 0.01 * (double) v36_maxGoldHeld));

                int f692_health;
                if (fE_level == 1) {
                    f692_health = v30_creatureDataObj->health;
                } else {
                    f692_health = v30_creatureDataObj->health * g_pObj6F2550->healthMultiplier_byLevel[fE_level] / 100;
                }
                v53_creature->processTakeDamage(
                        (__int64) ((double) v68_goodCr.initialHealth * 0.01 * (double) (unsigned int) f692_health)
                        - v53_creature->f3C_health,
                        g_goodPlayerId,
                        0);

                int v38_count = v69_count;
                if ((BYTE) v69_count) {
                    int v39_count = v69_count;
                    do {
                        v53_creature->fun_48B120();
                        --v39_count;
                    } while (v39_count);
                }
                unsigned __int8 f1D_wanderRadius = v68_goodCr.wanderRadius;
                v53_creature->field_34 = 0;
                v53_creature->wanderRadius = f1D_wanderRadius;
                unsigned __int16 v41_goodAttackPlayerId = 0;
                v53_creature->partyId = v68_goodCr.partyId;
                if (v68_goodCr.objectiveTargetPlayerId)
                    v41_goodAttackPlayerId = self->playerList.players_7[v68_goodCr.objectiveTargetPlayerId - 1].f0_tagId;
                if (!a4_bool || v38_count) {
                    v53_creature->setGoodJob(
                            v68_goodCr.objective_goodJob,
                            v41_goodAttackPlayerId,
                            v68_goodCr.objectiveTargetActionPointId);
                } else {
                    v53_creature->setGoodJob(19, v41_goodAttackPlayerId, v68_goodCr.objectiveTargetActionPointId);
                }
                unsigned int fF_behaviourFlags = v68_goodCr.behaviourFlags;
                v53_creature->setWillFight(v68_goodCr.behaviourFlags & 1);
                v53_creature->setLeader((fF_behaviourFlags >> 1) & 1);
                v53_creature->setFollower((fF_behaviourFlags >> 2) & 1);
                v53_creature->setWillBeAttacked((fF_behaviourFlags >> 3) & 1);
                v53_creature->setActAsDropped((fF_behaviourFlags >> 6) & 1);
                v53_creature->setStartAsDying(fF_behaviourFlags >> 7);
                v53_creature->setFreeFriendsOnJaiBreak((fF_behaviourFlags >> 5) & 1);
                unsigned int f1F_behaviourFlags2 = v68_goodCr.behaviourFlags2;
                v53_creature->setDestroyRooms(v68_goodCr.behaviourFlags2 & 1);
                v53_creature->setIAmaTool((f1F_behaviourFlags2 & 2) != 0);
                v53_creature->setIAmAMercenary((f1F_behaviourFlags2 >> 3) & 1);
                v53_creature->setDiesInstantly((f1F_behaviourFlags2 & 4) != 0);
                __int16 f18_triggerId = v68_goodCr.triggerId;
                v53_creature->setTriggerId(v68_goodCr.triggerId);
                if (f18_triggerId) {
                    self->_set_trigger_flag_sub_519A20(f18_triggerId, 1);
                }
                v53_creature->fun_49AA30(3, 0, 0);
                if (v55_bool) {
                    v53_creature->setCurrentState_48AD30(269);
                    v53_creature->renderInfo._flags2 &= ~1u;
                }
            }
            ++v23_goodIdx;
            if (v23_goodIdx >= 0x10) {
                finalizeSpawnParty(self, v57_player, a2_heroPartyIdx, v55_bool);
                return 1;
            }
        }
    }

}

int dk2::CWorld::WorldTrigger_cpp_519F90(__int16 a2_heroPartyIdx, int a3_actionPointId, int a4_bool) {
    if ((BYTE) a4_bool != 0) {
        CPlayer *fA_players_7 = this->playerList.players_7;
        for (CCreature *i = (CCreature *) sceneObjects[fA_players_7->ownedCreature_first]; i;
             i = (CCreature *) sceneObjects[i->fC_playerNodeY]) {
            if (i->partyId == (uint8_t) a2_heroPartyIdx
                && !i->prisonOwner
                && (i->stateFlags & 0x200000) == 0  // creatureDying
                    )
                return 1;
        }
    }
    return spawnWholeParty(this, (uint8_t) a2_heroPartyIdx, a3_actionPointId, (uint8_t) a4_bool);
}

BOOL dk2::CWorld::checkAllowObjectToDrop_509340(
        int x,
        int y,
        uint16_t playerTagId,
        int objTypeId) {
    return this->cmap.checkAllowObjectToDrop_450BE0(x, y, playerTagId, objTypeId);
}
