//
// Created by DiaLight on 21.08.2024.
//
#include "dk2/MyComputerPlayer.h"
#include "dk2/entities/CCreature.h"
#include "dk2/entities/CPlayer.h"
#include "dk2/entities/CRoom.h"
#include "dk2/utils/Pos2us.h"
#include "dk2/entities/data/MyCreatureDataObj.h"
#include "dk2/world/nav/MyNavigationSystem.h"
#include "dk2/world/map/MyMapElement.h"
#include "dk2_globals.h"
#include "patches/micro_patches.h"
#include "MyComputerPlayer_drop_condition.h"
#include "computer_player_flags.h"
#include "dk2/entities/CCreatureExtended.h"
#include "dk2/entities/player/MyTask.h"
#include "dk2/entities/player/MyTaskStack.h"
#include "dk2_functions.h"

int abs32(int v) {
    return v < 0 ? -v : v;
}

namespace dk2 {

    void updateFlags_finishTask(dk2::MyComputerPlayer *cp) {
        uint32_t flags = cp->flags;

        {  // increment current task
            int cet = currentEventTask_fromFlags(flags);
            cet = (cet + 1) % 3;
            flags = currentEventTask_toFlags(cet) | flags & ~MCPF_CurrentEventTask;
        }

        {  // decrement num tasks
            int noet = numberOfEventTasks_fromFlags(flags);
            noet = noet - 1;
            flags = numberOfEventTasks_toFlags(noet) | flags & ~MCPF_NumberOfEventTasks;
        }

        cp->flags = flags;
    }

    uint32_t getMaxHealth(CCreature *i_creature) {
        uint32_t maxHealth = i_creature->level == 1
                ? i_creature->creatureData->health
                : i_creature->creatureData->health
                * g_pObj6F2550->healthMultiplier_byLevel[(unsigned __int8) i_creature->level]
                / 100;
        return maxHealth;
    }

    uint32_t getDefenceLevel(CCreature *i_creature) {
        int16_t defenceLevel = i_creature->level == 1
                ? i_creature->creatureData->_threatLevel
                : i_creature->creatureData->_threatLevel
                * g_pObj6F2550->_threatLevelMultiplier[(unsigned __int8) i_creature->level]
                / 100;
        return defenceLevel;
    }

    void moveCreaturesToThreat(dk2::MyComputerPlayer *cp, char a2_tendancySpeed) {
        while (a2_tendancySpeed) {
            int totalNumberOfOwnedCreatures = cp->cplayer->totalNumberOfOwnedThings[0];
            if (!totalNumberOfOwnedCreatures) {
                updateFlags_finishTask(cp);
                return;
            }
            CCreature *i_creature;
            for(
                    i_creature = (CCreature *) sceneObjects[cp->cplayer->ownedCreature_first];
                    i_creature;
                    i_creature = (CCreature *) sceneObjects[i_creature->fC_playerNodeY]) {
                uint32_t dataFlags = i_creature->creatureData->flags;
                if ((dataFlags & 1) != 0) continue;
                if ((dataFlags & 0x4000) != 0) continue;
                if (i_creature->fun_4888C0_checkState()) continue;
                if (!i_creature->fun_45A6D0(0)) continue;
                if (i_creature->f3C_health <= (int) (getMaxHealth(i_creature) / 4)) continue;
                char v25 = g_stateEntries[i_creature->cstate.currentStateId].f16;
                if (v25 == 7 || v25 == 3) continue;
                if (i_creature->f3C_health <= (int) (getMaxHealth(i_creature) / 2)) continue;
                if (i_creature->cstate.fun_478050() == 22) continue;
                if (cp->cplayer->hasThingInHand(i_creature->f0_tagId)) continue;
                if (i_creature->cstate.currentStateId == 76) continue;
                if (i_creature->fun_48F350()) continue;
                if ((i_creature->creatureData->flags & 1) != 0) continue;  // IsWorker
                if(patch::blocking_response_to_threat_fix::enabled) {
//                    if ((i_creature->creatureData->flags & 2) == 0) continue;  // !CanBePickedUp
#if UseExtendedCreature
                    if(((dk2ex::CCreatureExtended *) i_creature)->decrementDropSelectPenalty(totalNumberOfOwnedCreatures)) continue;
#endif
                }
                break;  // creature to drop found
            }
            --a2_tendancySpeed;
            if (!i_creature) {
                MyRespondToAttack *mrta = &cp->respondToAttack[getCurrentEventTask(cp)];
//                printf("nothing to drop thr=%d\n", mrta->_threatLevel);
                updateFlags_finishTask(cp);
                return;
            }
            if (i_creature->_belongsTo(cp->cplayer->f0_tagId)) {
                dk2::Vec3i dropLoc = {0, 0, 0};
                {
                    MyRespondToAttack *mrta = &cp->respondToAttack[getCurrentEventTask(cp)];
                    dropLoc.x = (mrta->x << 12) + 2048;
                    dropLoc.y = (mrta->y << 12) + 2048;
                    dropLoc.z = 0;
                }

                bool doMove = false;
                uint16_t playerTagId = cp->world->v_getMapElem_2(&dropLoc)->_playerIdFFF & 0xFFF;

                if(patch::response_to_threat_fix::enabled) {
                    // I think it is dk2 devs mistake due to carelessness
                    // v1.5.1 does not have it
                    if (playerTagId == cp->cplayer->f0_tagId) {
                        doMove = drop_condition(cp, dropLoc);
                    }
                } else {
                    if (playerTagId != cp->cplayer->f0_tagId) {
                        doMove = drop_condition(cp, dropLoc);
                    }
                }
                if (doMove) {
                    cp->cplayer->fun_4BFBD0(i_creature);
                    cp->cplayer->takeThingInHand(i_creature->f0_tagId);
                    if (cp->cplayer->hasThingInHand(i_creature->f0_tagId)) {
                        dropLoc.x += 256;
                        dropLoc.y += 256;
                        uint16_t v74_direction = 0;
                        cp->cplayer->dropThingFromHand(&dropLoc, &v74_direction);
                    }
                }
                MyRespondToAttack *mrta = &cp->respondToAttack[getCurrentEventTask(cp)];
//                printf("drop id=%d thr=%d def=%d dfl=%08X at %d,%d\n", i_creature->f0_tagId,
//                       mrta->_threatLevel,
//                       getDefenceLevel(i_creature),
//                       i_creature->creatureData->flags,
//                       i_creature->f16_pos.x >> 12,
//                       i_creature->f16_pos.y >> 12
//                );
                mrta->_threatLevel -= getDefenceLevel(i_creature);
            } else {
                if(patch::blocking_response_to_threat_fix::enabled) {
#if UseExtendedCreature
                    ((dk2ex::CCreatureExtended *) i_creature)->setDropSelectPenalty(totalNumberOfOwnedCreatures);
#endif
                }
                MyRespondToAttack *mrta = &cp->respondToAttack[getCurrentEventTask(cp)];
//                printf("!drop id=%d thr=%d def=%d dfl=%08X at %d,%d tnooc=%d\n", i_creature->f0_tagId,
//                       mrta->_threatLevel,
//                       getDefenceLevel(i_creature),
//                       i_creature->creatureData->flags,
//                       i_creature->f16_pos.x >> 12,
//                       i_creature->f16_pos.y >> 12,
//                       totalNumberOfOwnedCreatures
//                );
            }
            MyRespondToAttack *mrta = &cp->respondToAttack[getCurrentEventTask(cp)];
            if (mrta->_threatLevel <= 0) {
                mrta->_threatLevel = 0;
                updateFlags_finishTask(cp);
                return;
            }
        }
    }
    void moveCreaturesBack(dk2::MyComputerPlayer *cp, char a2_tendancySpeed) {
        while (a2_tendancySpeed) {
            if (!cp->cplayer->totalNumberOfOwnedThings[0]) {
                updateFlags_finishTask(cp);
                return;
            }
            CCreature *i_creature;
            for (i_creature = (CCreature *) sceneObjects[cp->cplayer->ownedCreature_first];
                 i_creature;
                 i_creature = (CCreature *) sceneObjects[i_creature->fC_playerNodeY]) {
                MyRespondToAttack *mrta = &cp->respondToAttack[getCurrentEventTask(cp)];
                int locY = (mrta->y << 12) + 2048;
                int locX = (mrta->x << 12) + 2048;

                int deltaX = abs32(i_creature->f16_pos.x - locX);
                int deltaY = abs32(i_creature->f16_pos.y - locY);
                int radius = 5;

                int sqrX = (uint64_t) (deltaX * (__int64) deltaX) >> 12;
                int sqrY = (uint64_t) (deltaY * (__int64) deltaY) >> 12;
                int sqrR = (radius * radius) >> 12;
                bool inRadius = (sqrY + sqrX) < sqrR;

                uint32_t dataFlags = i_creature->creatureData->flags;
                if(!inRadius) continue;
                if((dataFlags & 0x4000) != 0) continue;
                if(i_creature->fun_4888C0_checkState()) continue;
                if(!(i_creature->lastDroppedCounter > 300u || cp->world->getGameTick() <= 300)) continue;
                if(cp->cplayer->hasThingInHand(i_creature->f0_tagId)) continue;
                if (i_creature->cstate.currentStateId == 76) continue;
                break;  // found creature to drop
            }
            --a2_tendancySpeed;
            if (!i_creature) {
                MyRespondToAttack *mrta = &cp->respondToAttack[getCurrentEventTask(cp)];
//                printf("nothing to save thr=%d\n", mrta->_threatLevel);
                updateFlags_finishTask(cp);
                return;
            }
            if (i_creature->_belongsTo(cp->cplayer->f0_tagId)) {
                cp->cplayer->fun_4BFBD0(i_creature);
                cp->cplayer->takeThingInHand(i_creature->f0_tagId);
                if (cp->cplayer->hasThingInHand(i_creature->f0_tagId)) {
                    Vec3i dropLoc = {0, 0, 0};
                    {
                        Pos2us *dungeonHeartPosition = cp->cplayer->getDungeonHeartPosition();
                        dropLoc.x = (dungeonHeartPosition->x << 12) + 2048;
                        dropLoc.y = (dungeonHeartPosition->y << 12) + 2048;
                        dropLoc.z = 0;
                    }
                    dropLoc.x += 256;
                    dropLoc.y += 256;
                    uint16_t v74_direction = 0;
                    cp->cplayer->dropThingFromHand(&dropLoc, &v74_direction);
                }
                MyRespondToAttack *mrta = &cp->respondToAttack[getCurrentEventTask(cp)];
//                printf("save thr=%d def=%d\n", mrta->_threatLevel, getDefenceLevel(i_creature));
                mrta->_threatLevel += getDefenceLevel(i_creature);
            } else {
                MyRespondToAttack *mrta = &cp->respondToAttack[getCurrentEventTask(cp)];
//                printf("!save thr=%d def=%d\n", mrta->_threatLevel, getDefenceLevel(i_creature));
            }
            MyRespondToAttack *mrta = &cp->respondToAttack[getCurrentEventTask(cp)];
            if (mrta->_threatLevel >= 0) {
                mrta->_threatLevel = 0;
                updateFlags_finishTask(cp);
                return;
            }
        }
    }
}
char dk2::MyComputerPlayer::tickRespondToAttack(char a2_tendancySpeed) {
    if (this->respondToAttack[getCurrentEventTask(this)]._threatLevel >= 0) {
        if (!a2_tendancySpeed) return 0;
        moveCreaturesToThreat(this, a2_tendancySpeed);
        return 0;
    }
    moveCreaturesBack(this, a2_tendancySpeed);
    return 0;
}

int dk2::MyComputerPlayer::tick() {
    if (this->cplayer->status == 1 || this->cplayer->status == 3) return 0;
    uint8_t tendancySpeedLeft = this->tendancySpeed;
    this->taskTimeCounter++;
    if (((this->flags & MCPF_TimesOut) != 0) && this->taskTimeCounter > 1680) {
        this->taskTimeCounter = 0;
        this->flags = this->flags & ~MCPF_Task | task_toFlags(0);
        this->flags = this->flags & ~MCPF_NextTask | nextTask_toFlags(0);
    }
    if (this->untagGoldCounter) {
        this->untagGoldCounter--;
        if (this->untagGoldCounter == 0) {
            dk2::MyTask task;
            if (this->cplayer->taskStack->getTaskByListHeadIdx(2u, (char *)&task) ) {
                do {
                    GameAction action;
                    action.data1 = *(DWORD *)&task.positionX;
                    action.data2 = *(DWORD *)&task.positionX;
                    action.data3 = 0;
                    action.actionKind = 41;
                    action.playerTagId = this->cplayer->f0_tagId;
                    CWorld *fA_world = this->world;
                    int tryLevel = 0;
                    int handlerResult = fA_world->callActionHandler(&action);
                    tryLevel = -1;
                    if (handlerResult == 0)
                        this->untagGoldCounter = 1;
                } while (this->cplayer->taskStack->getTaskByIdx(task.id, &task));
            }
        }
    }
    if (this->cannotAttackCounter) this->cannotAttackCounter--;
    if (this->callToArmsCounter) this->callToArmsCounter--;
    this->handlePlayerMessages_4FA400();

    int numberOfEventTasks = getNumberOfEventTasks(this);
    if (numberOfEventTasks != 0) {
        while (tendancySpeedLeft) {
            int cet = getCurrentEventTask(this);
            uint32_t taskId = this->eventTasks[cet];
            if (taskId != 1) {
                tendancySpeedLeft = 0;
                break;
            }
            tendancySpeedLeft = this->tickRespondToAttack(tendancySpeedLeft);
        }
    }
    if (tendancySpeedLeft) {
        if (this->playersAttackedFlags) {
            tendancySpeedLeft = this->fun_4FECE0(tendancySpeedLeft);
        }
        if (tendancySpeedLeft) {
            if ((this->flags & MCPF_CallToArmsInUse) != 0)
                this->fun_4FEFC0();
            tendancySpeedLeft = this->fun_4FF260(tendancySpeedLeft);
        }
    }

    this->fun_500520();
    uint32_t rand64 = randomInt(
            0x64u, &this->world->gameSeed,
            "D:\\Dev\\DK2\\Projects\\Source\\Game\\ComputerPlayer.cpp", 5751);
    if (tendancySpeedLeft) {
        if (rand64 < 0x32) {
            if ( !this->fun_4FAB10() ) {
                tendancySpeedLeft = this->fun_4FF5C0_drop1_1(tendancySpeedLeft);
            }
        }

        uint32_t rand64 = randomInt(
                0x64u, &this->world->gameSeed,
                "D:\\Dev\\DK2\\Projects\\Source\\Game\\ComputerPlayer.cpp", 5759);
        if (rand64 < 0xA) {
            tendancySpeedLeft = this->def_5000A0(tendancySpeedLeft);
        }
        if (tendancySpeedLeft && (this->flagsFFFF & 0x10) != 0) {
            if ((this->flags & MCPF_FightGoingOn) != 0) {
                tendancySpeedLeft = this->def_503060(tendancySpeedLeft);
            } else {
                int v15_numberOfImps = this->cplayer->GetNumberOfCreaturesOfType(1u);
                if ( v15_numberOfImps < this->maximumImps ) {
                    if ( this->cplayer->dungeonArea / this->tilesPerImpRatio > v15_numberOfImps ) {
                        bool randBool1 = randomInt(
                                2u, &this->world->gameSeed,
                                "D:\\Dev\\DK2\\Projects\\Source\\Game\\ComputerPlayer.cpp", 5779) != 0;
                        bool randBool2 = randomInt(
                                2u, &this->world->gameSeed,
                                "D:\\Dev\\DK2\\Projects\\Source\\Game\\ComputerPlayer.cpp", 5780) != 0;
                        Pos2us *dhPos = this->cplayer->getDungeonHeartPosition();
                        Vec3i vec = {0, 0, 0};
                        vec.x = ((dhPos->x + (randBool1 ? -2 : 2)) << 12) + 2048;
                        vec.y = ((dhPos->y + (randBool2 ? -2 : 2)) << 12) + 2048;
                        vec.z = 0;
                        if (this->cplayer->fun_4BAFA0(4u) == 3 && this->cplayer->fun_4BBD30(4, &vec, NULL)) {
                            --tendancySpeedLeft;
                        }
                    }
                }
            }
        }
    }

    uint32_t rand3 = randomInt(3u, &this->world->gameSeed, "D:\\Dev\\DK2\\Projects\\Source\\Game\\ComputerPlayer.cpp", 5795);
    if(tendancySpeedLeft) {
        if (rand3 >= getProbabilityOfMovingCreatureForResearch(this) && (this->flagsFFFF & 4) != 0 ) {
            int v24_availableSpellCount = this->world->v_getAvailableSpellCount();
            for (int i = 1; i <= v24_availableSpellCount; ++i) {
                if (this->cplayer->fun_4BAFA0(i) != 2) continue;
                CRoom *ignore;
                if ( this->cplayer->findRoomOfType(6, &ignore) )
                    this->fun_4FA8D0();
                break;
            }
            if ( getNumberOfEventTasks(this) != 0 && this->eventTasks[getCurrentEventTask(this)] != 1
                 || getNumberOfEventTasks(this) == 0 ) {
                tendancySpeedLeft = this->fun_503690(tendancySpeedLeft);
            }
        }
    }
    if (!tendancySpeedLeft) return 1;

    if ((this->flagsFFFF & 0x20) != 0) {
        tendancySpeedLeft = this->fun_502F00(tendancySpeedLeft);
    }
    if (!tendancySpeedLeft) return 1;

    tendancySpeedLeft = this->fun_5006D0(tendancySpeedLeft);
    if (!tendancySpeedLeft) return 1;

    if ((this->flags2 & MCPF2_UseSightOfEvil) != 0) {
        tendancySpeedLeft = this->fun_5003A0(tendancySpeedLeft);
    }
    while (tendancySpeedLeft) {
        switch (getTask(this)) {
            case 0:
                --tendancySpeedLeft;
                if (!this->fun_4FAEF0() && (this->flagsFFFF & 1) != 0)
                    this->fun_4FC690();
                if (getTask(this) == 0 && (this->flagsFFFF & 2) != 0) {
                    CPlayer *v28 = this->cplayer;
                    if (v28->money < (unsigned int)this->tendancyMoney && !v28->taskStack->numberInTaskList[2]) {
                        this->fun_4FD590();
                    }
                }
                break;
            case 1:
                tendancySpeedLeft = this->fun_4FCE70(tendancySpeedLeft);
                break;
            case 2:
                tendancySpeedLeft = this->fun_4FD030(tendancySpeedLeft);
                break;
            case 3:
                tendancySpeedLeft = this->fun_4FD2B0(tendancySpeedLeft);
                break;
            case 4:
                --tendancySpeedLeft;
                if ((this->flagsFFFF & 2) != 0) {
                    CPlayer *v29 = this->cplayer;
                    if (v29->money < (unsigned int) this->tendancyMoney && !v29->taskStack->numberInTaskList[2]) {
                        this->fun_4FD590();
                    }
                }
                if (getTask(this) == 4) {
                    this->taskTimeCounter = 0;
                    this->flags = this->flags & ~MCPF_Task | task_toFlags(0);
                }
                break;
            case 5:
                tendancySpeedLeft = this->fun_4FD660(tendancySpeedLeft);
                break;
            case 6:
                tendancySpeedLeft = this->fun_4FD750(tendancySpeedLeft);
                break;
            case 7:
                tendancySpeedLeft = this->fun_4FDC50(tendancySpeedLeft);
                break;
            case 8:
                tendancySpeedLeft = 0;
                break;
            default:
                this->taskTimeCounter = 0;
                this->flags = this->flags & ~MCPF_Task | task_toFlags(4);
                tendancySpeedLeft = 0;
                break;
        }  // switch
    }  // while
    return 1;
}

