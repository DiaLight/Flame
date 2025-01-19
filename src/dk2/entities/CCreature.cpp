//
// Created by DiaLight on 02.08.2024.
//

#include "dk2/entities/CCreature.h"
#include "dk2/entities/CObject.h"
#include "dk2/entities/CPlayer.h"
#include "dk2/entities/CDoor.h"
#include "dk2/entities/CTrap.h"
#include "dk2/entities/data/MyCreatureDataObj.h"
#include "dk2/entities/data/MyDoorDataObj.h"
#include "dk2/entities/data/MyTrapDataObj.h"
#include "dk2/entities/data/MyObjectDataObj.h"
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "patches/micro_patches.h"
#include "creature_state.h"
#include "entities_type.h"


int dk2::CCreature::processDealDamage() {
    MyCreatureDataObj *f370_creatureData = this->creatureData;
    this->stateFlags2 &= ~StateFlags2_PlayInstanceAnimation;
    if(((unsigned int)f370_creatureData->flags >> 29) & 1) {  // maybe can play animation
        this->stateFlags2 |= StateFlags2_PlayInstanceAnimation;
    }
    if ( this->stateFlags & StateFlags1_Possessed ) {
        int v4 = f370_creatureData->f5CA;
        if ( g_pWorld->getGameTick() <= this->inst.startTime + v4 - 1 ) return 1;
    }
    int fC_data1 = this->inst.data1;
    if ( !sceneObjectsPresent[fC_data1] ) return 0;
    CPhysicalThing *v7_target = (CPhysicalThing *)sceneObjects[fC_data1];
    if (v7_target->f12_mapWhoType == 2 ) return 0;
    int v8_damage = -this->creatureData->sub_494D00(this);
    if ( !v7_target->v_f34() ) return 0;
    Vec3i f16_pos;
    memset(&f16_pos, 0, sizeof(f16_pos));
    int v25;
    if ( !g_pWorld->profiler->c_bridge->v_f10C(this, 0, &f16_pos, &v25)) f16_pos = v7_target->f16_pos;
    if (v7_target->fE_type == 0 ) {  // CCreature
        CCreature *targetCreature = (CCreature *) v7_target;
        if (targetCreature->fun_4E0460() && targetCreature->lairId ) {
            CObject *v9_object = (CObject *)sceneObjects[targetCreature->lairId];
            static_assert(CCreature_typeId_DarkAngel == 23);
            if ( v9_object->typeId == CCreature_typeId_DarkAngel ) {
                targetCreature->cstate.setCurrentState_476D30(84, 0);
            } else {
                v9_object->renderInfo._flags2 = v9_object->renderInfo._flags2 & 0xFE ^ 1;
                targetCreature->renderInfo._flags2 = targetCreature->renderInfo._flags2 & 0xFE ^ 1;
                int f1C_type = targetCreature->inst.type;
                BOOL v11 = f1C_type != 21 && f1C_type != 0;
                if ( v11 && g_Obj6E4198_arr[f1C_type].f1C )
                    targetCreature->inst.sub_4966A0();
                Vec3i v27;
                v27.x = v9_object->f16_pos.x;
                v27.y = v9_object->f16_pos.y;
                v27.z = v9_object->f16_pos.z;
                unsigned __int16 fF0_angle = v9_object->fF0_direction;
                int v14 = (-410 * fF0_angle) & 0x7FF;
                v27.x += g_angle2048_to_x[v14] >> 16;
                v27.y += g_angle2048_to_y[v14] >> 16;
                targetCreature->fun_4B5560(&v27);
                targetCreature->setCurrentState_48AD30(1);
            }
        }
        if ( targetCreature->invulnerableTimer ) return 0;
        this->sub_4998A0(this->creatureData->f77A, targetCreature->creatureData->f685, &f16_pos);
        if ( (this->creatureData->flags & 0x4000) != 0
             && targetCreature->f24_playerId == this->f24_playerId ) {
            this->fun_48F3F0();
            this->setCurrentState_48AD30(242);
            targetCreature->stateFlags &= ~StateFlags1_DeadBodyOnDestroy;
            targetCreature->v_f20_setHealth0();
            return 0;
        }
        if(!patch::disable_bonus_damage::enabled) {
            unsigned __int16 v24_angle2048 = asm_calcNegYAngle2048(
                    this->f16_pos.x - targetCreature->f16_pos.x,
                    this->f16_pos.y - targetCreature->f16_pos.y) & 0x7FF;
            if(patch::backstab_fix::enabled) {
                v24_angle2048 = (targetCreature->fF0_direction + 2048 - v24_angle2048) % 2048;
            }
            if (v24_angle2048 > 0x3FFu )
                v24_angle2048 = 2046 - v24_angle2048;
            int v17_angleDiv20 = (v24_angle2048 & 0x3FF) / 20;
            int v18_newDamage = v8_damage;
            if ( v17_angleDiv20 > 15 ) {
                v18_newDamage = v8_damage + v8_damage * v17_angleDiv20 / 100;
            }
//            printf("%d:%s:%d:%d->%d:%s:%d:%d damage=%d(+%d) vec:{%d,%d} a:%d(%d) degrees:%.2f\n",
//                   this->f24_playerId, CCreature_typeId_toString(this->typeId), this->f0_tagId, this->f3C_health,
//                   targetCreature->f24_playerId, CCreature_typeId_toString(targetCreature->typeId), targetCreature->f0_tagId, targetCreature->f3C_health,
//                   -v8_damage, -(v18_newDamage - v8_damage),
//                   this->f16_pos.x - targetCreature->f16_pos.x, this->f16_pos.y - targetCreature->f16_pos.y,
//                   v24_angle2048, v17_angleDiv20, (float) v24_angle2048 / 2048 * 360
//            );
            v8_damage = v18_newDamage;
        }
    }
    if (v7_target->fE_type == 4 )  // CDoor
        this->sub_4998A0(this->creatureData->f77A, ((CDoor *) v7_target)->typeData->fB3, &f16_pos);
    if (v7_target->fE_type == 3 )  // CTrap
        this->sub_4998A0(this->creatureData->f77A, ((CTrap *) v7_target)->typeData->fBF, &f16_pos);
    if (v7_target->fE_type == 2 )  // CObject
        this->sub_4998A0(this->creatureData->f77A, ((CObject *) v7_target)->typeObj->f11C, &f16_pos);
    if ( v8_damage ) {
        CPlayer *f26_pPlayer_owner = this->f26_pPlayer_owner;
        char v20 = f26_pPlayer_owner->cryptPowersPeopleActive[6];
        if ( v20 > 0 )
            v8_damage = 10 * v8_damage * (v20 + 10) / 100;
        char v21 = f26_pPlayer_owner->cryptPowersPeopleActive[7];
        if ( v21 > 0 )
            v8_damage = v8_damage * (15 * v21 + 100) / 100;
        static_assert(CCreature_typeId_Monk == 19);
        if (this->typeId == CCreature_typeId_Monk && v7_target->fE_type == 0) {  // CCreature
            CCreature *targetCreature = (CCreature *) v7_target;
            targetCreature->stateFlags2 |= StateFlags2_CantBeResurrected;
            targetCreature->processTakeDamage(v8_damage, this->f24_playerId, 0);
            targetCreature->stateFlags2 &= ~StateFlags2_CantBeResurrected;
        } else {
            v7_target->processTakeDamage(v8_damage, this->f24_playerId, 0);
        }
        if ((this->creatureData->flags & 0x4000) != 0 && v7_target->fE_type == 0) {  // CCreature
            CCreature *targetCreature = (CCreature *) v7_target;
            static_assert(CCreature_typeId_StoneKnight == 28);
            if(targetCreature->typeId == CCreature_typeId_StoneKnight) {
                targetCreature->fun_490120(v8_damage, this->f24_playerId, 0);
            }
        }
    }
    if ( (this->creatureData->flags & 0x4000) != 0 ) {
        if ( v7_target->v_f28_hasNoHealth() )
            this->setCurrentState_48AD30(239);
    }
    this->field_2A = MySound_ptr->v_CSoundSystem_fun_5678F0(
            this->field_2A,
            this->creatureData->f6E3,
            219,
            &this->f16_pos);
    return 0;
}

namespace dk2 {
    bool calcIsAttackable(dk2::CCreature *self) {
        if(self->f12_mapWhoType == 2) return false;  // CObject
        if((self->stateFlags & 0x8000) != 0) return false;  // combatPitFighter
        if(self->cstate.currentStateId == 76) return false;  // 76: 2599"idle"
        if((self->stateFlags & 0x200000) != 0) return false;  // creatureDying
        if(self->v_f28_hasNoHealth()) return false;
        if(self->f12_mapWhoType == 2) return false;  // CObject
        if(self->fun_473990()) return false;
        if(self->fun_485210() && (self->stateFlags2 & 0x4000) == 0) return false;  // !tortureVoluntary
        if((self->stateFlags & 0x4000) != 0) return false;  // leaving
        if(self->invisibleTimer) return false;
        if((self->flags & 8) == 0) return false;  // !WILL_BE_ATTACKED
        if(patch::sleeping_possession_fix::enabled) {
            if((self->stateFlags & 0x80) == 0 &&  // !possessed
                    (g_stateEntries[self->cstate.currentStateId].seFlags & 4) != 0) return false;
        } else {
            if((g_stateEntries[self->cstate.currentStateId].seFlags & 4) != 0) return false;
        }
        // what for is this logic?
        for (int i = 0; i < 8; ++i) {
            if (self->fight.rangeAttackers[i] && self->fight.meleeAttackers[i]) continue;
            return true;
        }
        return false;
    }
}

void dk2::CCreature::updateIsAttackable() {
    if(calcIsAttackable(this)) {
        this->stateFlags2 |= 0x40;  // isAttackable
    } else {
        this->stateFlags2 &= ~0x40;  // !isAttackable
    }
}
