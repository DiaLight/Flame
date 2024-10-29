//
// Created by DiaLight on 27.10.2024.
//

#ifndef FLAME_DROP_THING_FROM_HAND_FIX_H
#define FLAME_DROP_THING_FROM_HAND_FIX_H

#include "dk2/entities/CPlayer.h"
#include "dk2/entities/CThing.h"
#include "dk2/ObjUnderHand.h"
#include "dk2/CDefaultPlayerInterface.h"


namespace drop_thing_from_hand_fix {

    extern bool enabled;
    void init(dk2::CPlayer *player);
    void modifyCheckIdx(dk2::CDefaultPlayerInterface *dplif, dk2::CPlayer *player, int &thingInHandIdx);
    void commitThingDropped(dk2::CPlayer *player);
    void onPushDropThing(dk2::CPlayer *player);

    void dump(dk2::CDefaultPlayerInterface *a4_dplif, dk2::CPlayer *player, const char *name);
    void dump(dk2::CPlayer *player, dk2::CThing *thingInHand, dk2::ObjUnderHand *a3_underHand);
}


#endif //FLAME_DROP_THING_FROM_HAND_FIX_H
