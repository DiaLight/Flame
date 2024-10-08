//
// Created by DiaLight on 21.08.2024.
//
#include "dk2/MyComputerPlayer.h"
#include "dk2/entities/CCreature.h"
#include "dk2/entities/CPlayer.h"
#include "dk2/utils/Pos2us.h"
#include "dk2/CWorld.h"
#include "dk2/entities/data/MyCreatureDataObj.h"
#include "dk2/world/nav/MyNavigationSystem.h"
#include "dk2/world/map/MyMapElement.h"
#include "dk2_globals.h"
#include "patches/micro_patches.h"

int abs32(int v) {
    return v < 0 ? -v : v;
}

namespace dk2 {
    void updateFlags_failed(dk2::MyComputerPlayer *cp) {
        unsigned int v17_flags = ((((((cp->flags >> 14) & 0xFu) + 1) % 3) & 0xF) << 14) | cp->flags & 0xFFFC3FFF;
        cp->flags = v17_flags ^ (v17_flags ^
                                 ((((((((cp->flags >> 14) & 0xFu) + 1) % 3) & 0xF) << 14) & 0xFFFC0000 |
                                 cp->flags & 0xFFFC0000)
                                 - 1)) & 0x3C0000;
    }
    void updateFlags_success(dk2::MyComputerPlayer *cp) {
        unsigned int v16_flags = (((((cp->flags >> 14) & 0xFu) + 1) % 3) & 0xF) << 14;
        cp->flags = (v16_flags | cp->flags & 0xFFFC3FFF) ^ ((v16_flags | cp->flags & 0xFFFC3FFF) ^
                                                            ((v16_flags & 0xFFFC0000 |
                                                              cp->flags & 0xFFFC0000) - 1)) & 0x3C0000;
    }
    void tickRespondToAttack_part1(dk2::MyComputerPlayer *cp, char a2_tendancySpeed) {
        while (a2_tendancySpeed) {
            CPlayer *fE_cplayer = cp->cplayer;
            if (!fE_cplayer->totalNumberOfOwnedThings[0]) {
                updateFlags_success(cp);
                return;
            }
            CTag *v68_creature = sceneObjects[fE_cplayer->thingsOwnedList[0]];
            CCreature *v20_creature = (CCreature *) v68_creature;
            if (v68_creature) {
                do {
                    unsigned int f686_flags = v20_creature->creatureData->flags;
                    if ((f686_flags & 1) == 0
                        && (f686_flags & 0x4000) == 0
                        && !v20_creature->fun_4888C0_checkState()
                        && v20_creature->fun_45A6D0(0)) {
                        unsigned __int8 f403_level = v20_creature->level;
                        MyCreatureDataObj *f370_creatureData = v20_creature->creatureData;
                        int f3C_health = v20_creature->f3C_health;
                        unsigned __int8 v64_level = f403_level;
                        unsigned int v24_modHealth = f403_level == 1
                                                     ? f370_creatureData->health
                                                     : f370_creatureData->health
                                                       * g_pObj6F2550->healthMultiplier_byLevel[(unsigned __int8) v64_level]
                                                       / 100;
                        if (f3C_health > (int) (v24_modHealth >> 2)) {
                            char v25 = g_stateEntries[v20_creature->cstate.currentStateId].f16;
                            if (v25 != 7 && v25 != 3) {
                                unsigned __int8 v63_level = f403_level;
                                unsigned int v26_modHealth = f403_level == 1
                                                             ? f370_creatureData->health
                                                             : f370_creatureData->health
                                                               *
                                                               g_pObj6F2550->healthMultiplier_byLevel[(unsigned __int8) v63_level]
                                                               / 100;
                                if (f3C_health > (int) (v26_modHealth >> 1)
                                    && v20_creature->cstate.fun_478050() != 22
                                    && !cp->cplayer->fun_4BCAE0(v20_creature->f0_tagId)
                                    && v20_creature->cstate.currentStateId != 76
                                    && !v20_creature->fun_48F350()
                                    && (v20_creature->creatureData->flags & 1) == 0) {
                                    break;
                                }
                            }
                        }
                    }
                    v20_creature = (CCreature *) sceneObjects[v20_creature->fC_playerNodeY];
                } while (v20_creature);
                v68_creature = (CTag *) v20_creature;
            }
            --a2_tendancySpeed;
            if (!v20_creature) {
                updateFlags_failed(cp);
                return;
            }
            if (v20_creature->sub_48E6A0_dif(cp->cplayer->f0_tagId)) {
                int v27_doDrop = 0;
                if(response_to_threat_fix::enabled) {
                    // dirty fix. better is to understand why devs made v27_doDrop condition
                    // v1.5.1 does not have it
                    v27_doDrop = 1;
                }
                int v28_respondIdx = (cp->flags >> 14) & 0xF;
                Vec3i v59_loc;
                memset(&v59_loc, 0, sizeof(v59_loc));
                unsigned __int16 v29_locX = cp->respondToAttack[v28_respondIdx].x;
                int v61_zero = 0;
                unsigned __int16 v30_locY = cp->respondToAttack[v28_respondIdx].y;
                v59_loc.z = 0;
                v59_loc.x = (v29_locX << 12) + 2048;
                CWorld *fA_world = cp->world;
                v59_loc.y = (v30_locY << 12) + 2048;
                if ((fA_world->v_getMapElem_2(&v59_loc)->_playerIdFFF & 0xFFF) != cp->cplayer->f0_tagId) {
                    unsigned int v71_locX = 0;
                    unsigned int v69_locY = 0;
                    int v32_respondIdx = (cp->flags >> 14) & 0xF;
                    bool v74_whileBool = true;
                    unsigned int v33_locX = cp->respondToAttack[v32_respondIdx].x;
                    unsigned __int16 v34_locY = cp->respondToAttack[v32_respondIdx].y;
                    CWorld *v35_cworld = cp->world;
                    unsigned int v73_locY = v34_locY;
                    CWorld *v36_cworld = v35_cworld;
                    int v37_cmapHeight = v35_cworld->v_getCMapHeight_508FB0();
                    unsigned int v65_cmapHeight = v37_cmapHeight;
                    unsigned int v39_cmapWidth = v36_cworld->v_getCMapWidth_508FA0();
                    CWorld *v40_cworld = cp->world;
                    int v41_maxSize;
                    if (v39_cmapWidth <= v65_cmapHeight)
                        v41_maxSize = v40_cworld->v_getCMapHeight_508FB0();
                    else
                        v41_maxSize = v40_cworld->v_getCMapWidth_508FA0();
                    int v62_maxSize_x2 = 2 * v41_maxSize;
                    if (cp->world->v_loc_509090(v33_locX, v73_locY)) {
                        CWorld *v42_cworld = cp->world;
                        MyMapElement *v43_mapElement = &v42_cworld->cmap.mapElements[v33_locX +
                                                                                     v73_locY * v42_cworld->cmap.width];
                        if ((v42_cworld->cmap.pNavigationSystem->map.ptr_ui8[
                                     v73_locY * v42_cworld->cmap.pNavigationSystem->map.width + v33_locX] & 8) == 0
                            && !v43_mapElement->sub_454110()
                            && (v43_mapElement->_playerIdFFF & 0xFFF) == cp->cplayer->f0_tagId) {
                            v71_locX = v33_locX;
                            v69_locY = v73_locY;
                            v74_whileBool = false;
                        }
                    }
                    unsigned int v44_locX = v33_locX + 1;
                    unsigned int v66_deltaY = 0;
                    int f3C_health = 0;
                    v27_doDrop = 1;
                    v65_cmapHeight = 1;
                    int v70 = 1;
                    int v72 = 1;
                    if (v74_whileBool) {
                        do {
                            if (f3C_health) {
                                while (true) {
                                    if (cp->world->v_loc_509090(v44_locX, v73_locY)) {
                                        CWorld *v48_cworld = cp->world;
                                        MyMapElement *v49_mapElem = &v48_cworld->cmap.mapElements[
                                                v44_locX + v73_locY * v48_cworld->cmap.width];
                                        if ((v48_cworld->cmap.pNavigationSystem->map.ptr_ui8[
                                                     v73_locY * v48_cworld->cmap.pNavigationSystem->map.width +
                                                     v44_locX] & 8) == 0
                                            && !v49_mapElem->sub_454110()
                                            && (v49_mapElem->_playerIdFFF & 0xFFF) == cp->cplayer->f0_tagId) {
                                            break;
                                        }
                                    }
                                    v44_locX += v66_deltaY;
                                    if (!--v72) {
                                        v65_cmapHeight = v66_deltaY;
                                        v72 = v70;
                                        f3C_health = 0;
                                        if (v70 < v62_maxSize_x2)
                                            goto LABEL_80;
                                        v71_locX = 0;
                                        goto LABEL_79;
                                    }
                                }
                            } else {
                                while (true) {
                                    if (cp->world->v_loc_509090(v44_locX, v73_locY)) {
                                        CWorld *v45_cworld = cp->world;
                                        MyMapElement *v46_mapElem = &v45_cworld->cmap.mapElements[
                                                v44_locX + v73_locY * v45_cworld->cmap.width];
                                        if ((v45_cworld->cmap.pNavigationSystem->map.ptr_ui8[
                                                     v73_locY * v45_cworld->cmap.pNavigationSystem->map.width +
                                                     v44_locX] & 8) == 0
                                            && !v46_mapElem->sub_454110()
                                            && (v46_mapElem->_playerIdFFF & 0xFFF) == cp->cplayer->f0_tagId) {
                                            break;
                                        }
                                    }
                                    bool v47 = v70 == 1;
                                    v73_locY += v65_cmapHeight;
                                    --v70;
                                    if (v47) {
                                        f3C_health = 1;
                                        v70 = ++v72;
                                        v66_deltaY = -v65_cmapHeight;
                                        goto LABEL_80;
                                    }
                                }
                            }
                            v71_locX = v44_locX;
                            v69_locY = v73_locY;
                            LABEL_79:
                            v74_whileBool = false;
                            LABEL_80:;
                        } while (v74_whileBool);
                        v27_doDrop = 1;
                    }
                    if (v71_locX) {
                        cp->respondToAttack[(cp->flags >> 14) & 0xF].x = v71_locX;
                        cp->respondToAttack[(cp->flags >> 14) & 0xF].y = v69_locY;
                        int v50_respondIdx = (cp->flags >> 14) & 0xF;
                        int v51_fl12Y = cp->respondToAttack[v50_respondIdx].y << 12;
                        v59_loc.x = (cp->respondToAttack[v50_respondIdx].x << 12) + 2048;
                        v59_loc.y = v51_fl12Y + 2048;
                        v59_loc.z = 0;
                    } else {
                        v27_doDrop = v61_zero;
                    }
                    v20_creature = (CCreature *) v68_creature;
                }
                if (v27_doDrop) {
                    cp->cplayer->fun_4BFBD0(v20_creature);
                    cp->cplayer->fun_4BC500(v20_creature->f0_tagId);
                    if (cp->cplayer->fun_4BCAE0(v20_creature->f0_tagId)) {
                        v59_loc.x += 256;
                        CPlayer *v52_cplayer = cp->cplayer;
                        v59_loc.y += 256;
                        uint16_t v74_direction = 0;
                        v52_cplayer->dropItemFromHand(&v59_loc, &v74_direction);
                    }
                }
                unsigned __int8 v53_level = v20_creature->level;
                MyCreatureDataObj *v54_creatureData = v20_creature->creatureData;
                int16_t v55_threatLevel;
                if (v53_level == 1)
                    v55_threatLevel = v54_creatureData->_threatLevel;
                else
                    v55_threatLevel = v54_creatureData->_threatLevel
                                      * g_pObj6F2550->_threatLevelMultiplier[(unsigned __int8) v53_level]
                                      / 100;
                cp->respondToAttack[(cp->flags >> 14) & 0xF]._threatLevel -= v55_threatLevel;
            }
            MyRespondToAttack *v56_respond = &cp->respondToAttack[(cp->flags >> 14) & 0xF];
            if (v56_respond->_threatLevel <= 0) {
                v56_respond->_threatLevel = 0;
                updateFlags_success(cp);
                return;
            }
        }
    }
    void tickRespondToAttack_part2(dk2::MyComputerPlayer *cp, char a2_tendancySpeed) {
        while (a2_tendancySpeed) {
            if (!cp->cplayer->totalNumberOfOwnedThings[0]) {
                updateFlags_failed(cp);
                return;
            }
            CCreature *i_creature;
            for (i_creature = (CCreature *) sceneObjects[cp->cplayer->thingsOwnedList[0]];
                 i_creature;
                 i_creature = (CCreature *) sceneObjects[i_creature->fC_playerNodeY]) {
                int v5_respondIdx = (cp->flags >> 14) & 0xF;
                int v6_locY = (cp->respondToAttack[v5_respondIdx].y << 12) + 2048;
                int v65_cmapHeight = abs32(
                        i_creature->f16_pos.x
                        - ((cp->respondToAttack[v5_respondIdx].x << 12)
                           + 2048));
                unsigned int v66_deltaY = abs32(i_creature->f16_pos.y - v6_locY);
                int f3C_health = (unsigned __int64) (v65_cmapHeight * (__int64) v65_cmapHeight) >> 12;
                int v68_value = ((unsigned __int64) ((int) v66_deltaY * (__int64) (int) v66_deltaY) >> 12);
                if (v68_value + f3C_health < 102400
                    && (i_creature->creatureData->flags & 0x4000) == 0
                    && !i_creature->fun_4888C0_checkState()
                    && (i_creature->lastDroppedCounter > 0x12Cu || cp->world->getGameTick() <= 0x12C)
                    && !cp->cplayer->fun_4BCAE0(i_creature->f0_tagId)
                    && i_creature->cstate.currentStateId != 76) {
                    break;
                }
            }
            --a2_tendancySpeed;
            if (!i_creature) {
                updateFlags_failed(cp);
                return;
            }
            if (i_creature->sub_48E6A0_dif(cp->cplayer->f0_tagId)) {
                cp->cplayer->fun_4BFBD0(i_creature);
                cp->cplayer->fun_4BC500(i_creature->f0_tagId);
                if (cp->cplayer->fun_4BCAE0(i_creature->f0_tagId)) {
                    CPlayer *v7_cplayer = cp->cplayer;
                    Vec3i v59_loc;
                    memset(&v59_loc, 0, sizeof(v59_loc));
                    Pos2us *dungeonHeartPosition = v7_cplayer->getDungeonHeartPosition();
                    Pos2us *v9_dungeonHeartPosition = cp->cplayer->getDungeonHeartPosition();
                    int v10_posY = (dungeonHeartPosition->y << 12) + 2048;
                    v59_loc.x = (v9_dungeonHeartPosition->x << 12) + 2304;
                    v59_loc.y = v10_posY + 256;
                    CPlayer *v11_cplayer = cp->cplayer;
                    v59_loc.z = 0;
                    uint16_t v74_direction = 0;
                    v11_cplayer->dropItemFromHand(&v59_loc, &v74_direction);
                }
                unsigned __int8 v12_level = i_creature->level;
                MyCreatureDataObj *v13_creatureData = i_creature->creatureData;
                int16_t v14_threatLevel;
                if (v12_level == 1)
                    v14_threatLevel = v13_creatureData->_threatLevel;
                else
                    v14_threatLevel = v13_creatureData->_threatLevel
                                      * g_pObj6F2550->_threatLevelMultiplier[(unsigned __int8) v12_level]
                                      / 100;
                cp->respondToAttack[(cp->flags >> 14) & 0xF]._threatLevel += v14_threatLevel;
            }
            MyRespondToAttack *v15_respond = &cp->respondToAttack[(cp->flags >> 14) & 0xF];
            if (v15_respond->_threatLevel >= 0) {
                v15_respond->_threatLevel = 0;
                updateFlags_success(cp);
                return;
            }
        }
    }
}
char dk2::MyComputerPlayer::tickRespondToAttack(char a2_tendancySpeed) {
    if (this->respondToAttack[(this->flags >> 14) & 0xF]._threatLevel >= 0) {
        if (!a2_tendancySpeed) return 0;
        tickRespondToAttack_part1(this, a2_tendancySpeed);
        return 0;
    }
    tickRespondToAttack_part2(this, a2_tendancySpeed);
    return 0;
}

