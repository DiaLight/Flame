//
// Created by DiaLight on 04.05.2025.
//
#include <dk2/MyCreatureCollection.h>
#include <dk2/entities/CCreature.h>
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "dk2_memory.h"
#include "dk2/entities/CCreatureExtended.h"

#define freeCreatures_count 448

int dk2::MyCreatureCollection::createCreatures(CWorld *world) {
    g_MyCreatureCollection_ptr = this;
    g_pWorld = world;
    this->firstCreatureId = 0;
    this->firstShotId = 0;
    this->firstObjectId = 0;
    this->firstDoorId = 0;
    this->firstActionPointId = 0;
    this->firstDeadBodyId = 0;
    this->firstEffectGeneratorId = 0;
    this->freeCreatureList = 0;
    sub_4A93A0();
    DWORD *creaturesBuf = (DWORD *) dk2::operator_new(
#if UseExtendedCreature
            sizeof(dk2ex::CCreatureExtended)
#else
            sizeof(CCreature)
#endif
            * freeCreatures_count
            + 4
    );
    CCreature *creatures = NULL;
    if (creaturesBuf) {
        creatures = (CCreature *) (creaturesBuf + 1);
        *creaturesBuf = freeCreatures_count;
#if UseExtendedCreature
        for_each_construct<dk2ex::CCreatureExtended, false>(creatures, freeCreatures_count);
#else
        for_each_construct<CCreature, false>(creatures, freeCreatures_count);
#endif
    }
    this->creatures = creatures;
    if (!creatures) return 0;

    if (MyResources_instance.playerCfg.kbLayoutId == 17)
        loadJcnKeyboard();
    this->pWorld = world;
    g_pWorld2 = world;
    for (unsigned int offs = 0; offs < freeCreatures_count; ++offs) {
#if UseExtendedCreature
        dk2ex::CCreatureExtended *f18_creatures = (dk2ex::CCreatureExtended *) this->creatures;
#else
        CCreature *f18_creatures = this->creatures;
#endif
        f18_creatures[offs].freeNodeX = 0;
        f18_creatures[offs].freeNodeY = 0;
        unsigned __int16 f0_tagId = f18_creatures[offs].f0_tagId;
        ((CCreature *) sceneObjects[f0_tagId])->freeNodeY = this->freeCreatureList;
        if (this->freeCreatureList)
            ((CCreature *) sceneObjects[this->freeCreatureList])->freeNodeX = f0_tagId;
        this->freeCreatureList = f0_tagId;
    }
    this->numberOfCreaturesCreated = 0;
    this->numberOfObjectsCreated = 0;
    this->numberOfDoorsCreated = 0;
    this->numberOfTrapsCreated = 0;
    this->numberOfShotsCreated = 0;
    this->numberOfActionPointsCreated = 0;
    this->numberOfDeadBodysCreated = 0;
    this->numberOfEffectGeneratorsCreated = 0;
    int result = this->objs.init(0xC0000u);
    if (!result)
        return result;
    result = 1;
    this->opened = 1;
    return result;
}

int dk2::MyCreatureCollection::fun_4B75C0() {
    for (int tagKind = 0; tagKind < 8; ++tagKind) {
        while (uint16_t tagId = (&this->firstCreatureId)[tagKind]) {
            if(!((CCreature *) sceneObjects[tagId])->v_fC_clear()) {
                return 0;
            }
        }
    }

    this->freeCreatureList = 0;
    for (unsigned int j = 0; j < freeCreatures_count; ++j ) {
#if UseExtendedCreature
        dk2ex::CCreatureExtended *f18_creatures = (dk2ex::CCreatureExtended *) this->creatures;
#else
        CCreature *f18_creatures = this->creatures;
#endif
        f18_creatures[j].freeNodeX = 0;
        f18_creatures[j].freeNodeY = 0;
        uint16_t f0_tagId = f18_creatures[j].f0_tagId;
        ((CCreature *) sceneObjects[f0_tagId])->freeNodeY = this->freeCreatureList;
        if ( this->freeCreatureList )
            ((CCreature *) sceneObjects[this->freeCreatureList])->freeNodeX = f0_tagId;
        this->freeCreatureList = f0_tagId;
    }
    this->numberOfCreaturesCreated = 0;
    return 1;
}

void dk2::MyCreatureCollection::clear() {
    for (int tagKind = 0; tagKind < 8; ++tagKind) {
        uint16_t &firstTagId = (&this->firstCreatureId)[tagKind];
        for (uint16_t tagId = firstTagId; firstTagId; tagId = firstTagId) {
            ((CThing *) sceneObjects[tagId])->v_f30_remove();
        }
    }
    if (this->creatures) {
        this->creatures->v_deleting_destructor(3);
        this->creatures = NULL;
    }
    g_pWorld2 = NULL;
    this->objs.destructor();
    g_pWorld = NULL;
    this->pWorld = NULL;
    this->opened = 0;
    g_MyCreatureCollection_ptr = NULL;
}

char *dk2::CCreature::deleting_destructor(char a2) {
    if ((a2 & 2) != 0) {
#if UseExtendedCreature
        for_each_destruct<dk2ex::CCreatureExtended, false>(this, ((DWORD *)this)[-1]);
#else
        for_each_destruct<dk2::CCreature, false>(this, ((DWORD *)this)[-1]);
#endif
        dk2::operator_delete((char *) this - 4);
        return (char *) this;
    } else {
        this->destructor();
        if ((a2 & 1) != 0)
            dk2::operator_delete(this);
        return (char *) this;
    }
}

void dk2::CCreature::constructor() {
    ((CThing *)this)->constructor();
    this->renderInfo.constructor();
    *(void **) this = &CPhysicalThing::vftable;
    this->lastPosition.constructor();
    *(void **) this = &CMovingThing::vftable;
    this->pilotNavigation.constructor();
    this->roomNodeX = 0;
    this->roomNodeY = 0;
    this->playerTorturedCreatureTypeListNodeX = 0;
    this->playerTorturedCreatureTypeListNodeY = 0;
    this->battleNodeX = 0;
    this->battleNodeY = 0;
    this->f246 = 0;
    this->freeNodeX = 0;
    this->freeNodeY = 0;
    this->cstate.constructor();
    this->inst.target.x = 0;
    this->inst.target.y = 0;
    this->inst.target.z = 0;
    *(void **) this = &CCreature::vftable;

#if UseExtendedCreature
    ((dk2ex::CCreatureExtended *) this)->constructorEx();
#endif
}
