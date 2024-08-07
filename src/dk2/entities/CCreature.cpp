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


#define CCreature_types(cb)\
    cb(1, true, Imp, imp)\
    cb(2, false, Prince, prince)\
    cb(3, true, BileDemon, bile_demon)\
    cb(4, true, Mistress, mistress)\
    cb(5, true, Warlock, warlock)\
    cb(6, true, DarkElf, dark_elf)\
    cb(7, true, Goblin, goblin)\
    cb(8, true, Vampire, vampire)\
    cb(9, true, Skeleton, skeleton)\
    cb(10, true, Troll, troll)\
    cb(11, true, Salamander, salamander)\
    cb(12, true, Firefly, firefly)\
    cb(13, false, Knight, knight)\
    cb(14, false, Dwarf, dwarf)\
    cb(15, false, Giant, giant)\
    cb(16, false, Wizard, wizard)\
    cb(17, false, Elf, elf)\
    cb(18, false, Thief, thief)\
    cb(19, false, Monk, monk)\
    cb(20, false, Fairy, fairy)\
    cb(21, false, King, king)\
    cb(22, true, BlackKnight, black_knight)\
    cb(23, true, DarkAngel, dark_angel)\
    cb(24, true, Rogue, rogue)\
    cb(25, false, Guard, guard)\
    cb(26, false, Prince_2, prince)\
    cb(27, true, Reaper, reaper)\
    cb(28, false, StoneKnight, stone_knight)\
    cb(29, false, Lord, lord)\
    cb(30, false, RoyalGuard, royal_guard)\
    cb(31, false, Prince_3, prince)\
    cb(32, true, Firefly_2, firefly)\
    cb(33, true, Goblin_2, goblin)\
    cb(34, true, Warlock_2, warlock)\
    cb(35, true, Troll_2, troll)\
    cb(36, true, DarkElf_2, dark_elf)\
    cb(37, true, Skeleton_2, skeleton)\
    cb(38, true, Mistress_2, mistress)\
    cb(39, true, Salamander_2, salamander)\
    cb(40, true, Rogue_2, rogue)\
    cb(41, true, BileDemon_2, bile_demon)\
    cb(42, true, Vampire_2, vampire)\
    cb(43, true, BlackKnight_2, black_knight)\
    cb(44, true, DarkAngel_2, dark_angel)


enum CCreature_typeId {
#define _CCreature_typeId(id, isEvil, pascalName, snakeName) CCreature_typeId_##pascalName = id,
    CCreature_types(_CCreature_typeId)
};

const char *CCreature_typeId_toString(int ty) {
    switch (ty) {
#define _CCreature_typeId_toString(id, isEvil, pascalName, snakeName) case CCreature_typeId_##pascalName: return #pascalName;
        CCreature_types(_CCreature_typeId_toString)
    }
    return "Unknown";
}



#define StateFlags1_InHand 0x00000001
#define StateFlags1_ContributesToPortalLimit 0x00000002
#define StateFlags1_AttackAbnormalTargets 0x00000004
#define StateFlags1_RebelActive 0x00000008
#define StateFlags1_RebelLeader 0x00000010
#define StateFlags1_DeadBodyOnDestroy 0x00000020
#define StateFlags1_LeaveNoTrace 0x00000040
#define StateFlags1_Possessed 0x00000080
#define StateFlags1_HeldByPossessed 0x00000100
#define StateFlags1_ThrownByPossessed 0x00000200
#define StateFlags1_BeingElectrocuted 0x00000400
#define StateFlags1_VampireIsBat 0x00000800
#define StateFlags1_Creeping 0x00001000
#define StateFlags1_Praying 0x00002000
#define StateFlags1_Leaving 0x00004000
#define StateFlags1_CombatPitFighter 0x00008000
#define StateFlags1_CannotLeaveHealthLoss 0x00010000
#define StateFlags1_IgnoringDoors 0x00020000
#define StateFlags1_IgnoringLockedRegion 0x00040000
#define StateFlags1_CheckingAllDoors 0x00080000
#define StateFlags1_CallToArmsOn 0x00100000
#define StateFlags1_CreatureDying 0x00200000
#define StateFlags1_FightProcessCounter 0x00400000
#define StateFlags1_WasLastDroppedOnARoom 0x04000000
#define StateFlags1_ShouldDelayGetUp 0x08000000
#define StateFlags1_FlyingCreatureMovingUp 0x10000000
#define StateFlags1_LeavingLava 0x20000000
#define StateFlags1_SkeletonFromSkeletonArmy 0x40000000
#define StateFlags1_SniperMode 0x80000000

#define StateFlags2_IsHypnotised 0x00000001
#define StateFlags2_AnimBackwards 0x00000002
#define StateFlags2_CantBeResurrected 0x00000004
#define StateFlags2_InfluencedByPossessed 0x00000008
#define StateFlags2_HasBeenConverted 0x00000010
#define StateFlags2_SkipNextPayment 0x00000020
#define StateFlags2_IsAttackable 0x00000040
#define StateFlags2_DestroysRooms 0x00000080
#define StateFlags2_IsTool 0x00000100
#define StateFlags2_IsMercenary 0x00000200
#define StateFlags2_HasBeenKnockedOut 0x00000400
#define StateFlags2_DieInstantly 0x00000800
#define StateFlags2_PlayInstanceAnimation 0x00001000
#define StateFlags2_CasinoGamblingFearless 0x00002000
#define StateFlags2_TortureVoluntary 0x00004000
#define StateFlags2_IsHasted 0x00008000
#define StateFlags2_IsSlowed 0x00010000
#define StateFlags2_IsOneShotReaper 0x00040000
#define StateFlags2_ReaperComplete 0x00080000
#define StateFlags2_Fleeing 0x00100000
#define StateFlags2_InWater 0x00200000



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
                targetCreature->cstate.fun_476D30(84, 0);
            } else {
                v9_object->renderInfo.fAF = v9_object->renderInfo.fAF & 0xFE ^ 1;
                targetCreature->renderInfo.fAF = targetCreature->renderInfo.fAF & 0xFE ^ 1;
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
                targetCreature->fun_48AD30(1);
            }
        }
        if ( targetCreature->invulnerableTimer ) return 0;
        this->sub_4998A0(this->creatureData->f77A, targetCreature->creatureData->f685, &f16_pos);
        if ( (this->creatureData->flags & 0x4000) != 0
             && targetCreature->f24_playerId == this->f24_playerId ) {
            this->fun_48F3F0();
            this->fun_48AD30(242);
            targetCreature->stateFlags &= ~StateFlags1_DeadBodyOnDestroy;
            targetCreature->v_f20();
            return 0;
        }
        if(!disable_bonus_damage::enabled) {
            unsigned __int16 v24_angle2048 = asm_calcNegYAngle2048(
                    this->f16_pos.x - targetCreature->f16_pos.x,
                    this->f16_pos.y - targetCreature->f16_pos.y) & 0x7FF;
            if(backstab_fix::enabled) {
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
        if ( v7_target->v_f28() )
            this->fun_48AD30(239);
    }
    this->field_2A = MySound_ptr->v_fun_5678F0(
            this->field_2A,
            this->creatureData->f6E3,
            219,
            &this->f16_pos);
    return 0;
}
