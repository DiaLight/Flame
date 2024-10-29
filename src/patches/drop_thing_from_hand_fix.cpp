//
// Created by DiaLight on 27.10.2024.
//

#include <sstream>
#include <iostream>
#include "drop_thing_from_hand_fix.h"
#include "dk2/entities/entities_type.h"
#include "dk2/entities/CObject.h"
#include "dk2_globals.h"

bool drop_thing_from_hand_fix::enabled = true;

namespace drop_thing_from_hand_fix {
    struct PlayerFix {
        int pendingToDropThings = 0;
    };
    PlayerFix players[7];
}

void drop_thing_from_hand_fix::init(dk2::CPlayer *player) {
    auto &fix = players[player->playerNumber];
    fix.pendingToDropThings = 0;
}

void drop_thing_from_hand_fix::modifyCheckIdx(dk2::CDefaultPlayerInterface *dplif, dk2::CPlayer *player, int &thingInHandIdx) {
    auto &fix = players[player->playerNumber];
    thingInHandIdx -= fix.pendingToDropThings;
    while(thingInHandIdx >= 0) {
        auto tagId = player->thingsInHand[thingInHandIdx];
        bool alreadyDropped = false;
        for (int i = 0; i < dplif->thingsInHand_count; ++i) {
            auto &tih = dplif->thingsInHand[i];
            if(tih.tagId != tagId) continue;
            if (!tih.dropped) continue;
            alreadyDropped = true;
            break;
        }
        if(!alreadyDropped) return;
        thingInHandIdx--;
        fix.pendingToDropThings++;
//        printf("force dont drop2 %d\n", fix.pendingToDropThings);
    }
}

void drop_thing_from_hand_fix::commitThingDropped(dk2::CPlayer *player) {
    auto &fix = players[player->playerNumber];
    fix.pendingToDropThings--;
    if(fix.pendingToDropThings < 0) fix.pendingToDropThings = 0;
}

void drop_thing_from_hand_fix::onPushDropThing(dk2::CPlayer *player) {
    auto &fix = players[player->playerNumber];
    fix.pendingToDropThings++;
}

void drop_thing_from_hand_fix::dump(dk2::CDefaultPlayerInterface *dplif, dk2::CPlayer *player, const char *name) {
    std::stringstream ss;
    ss << GetTickCount() << " " << name << " ";

    ss << "dplif:[";
    for (int i = 0; i < dplif->thingsInHand_count; ++i) {
        if(i != 0) ss << ", ";
        auto &tih = dplif->thingsInHand[i];
        auto &thing = *(dk2::CThing *) dk2::sceneObjects[tih.tagId];
        ss << CThing_type_toString(thing.fE_type);
        if(!dk2::sceneObjectsPresent[tih.tagId]) ss << " np";
        if(tih.hasUnderHand) ss << " uh";
        if(tih.dropped) ss << " dr";

        if(thing.fE_type == CThing_type_CObject) {}
    }
    ss << "], ";
    ss << "cpl:[";
    for (int i = 0; i < player->thingsInHand_count; ++i) {
        if(i != 0) ss << ", ";
        auto tagId = player->thingsInHand[i];
        auto &thing = *(dk2::CThing *) dk2::sceneObjects[tagId];
        ss << CThing_type_toString(thing.fE_type);
        if(!dk2::sceneObjectsPresent[tagId]) ss << " np";

        if(thing.fE_type == CThing_type_CObject) {}
    }
    ss << "]";
    std::cout << ss.str() << std::endl;
}
void drop_thing_from_hand_fix::dump(dk2::CPlayer *player, dk2::CThing *thingInHand, dk2::ObjUnderHand *a3_underHand) {
    auto &fix = players[player->playerNumber];
    printf("%d thingInHand [%d, %d] %d %s  %d", GetTickCount(), a3_underHand->x, a3_underHand->y, thingInHand->f0_tagId,
           CThing_type_toString(thingInHand->fE_type),
           fix.pendingToDropThings);
    if(thingInHand->fE_type == CThing_type_CObject) {
        dk2::CObject *object = (dk2::CObject *) thingInHand;
        printf(" obj.ty=%s", CObject_typeId_toString(object->typeId));
    }
    printf("\n");
}
