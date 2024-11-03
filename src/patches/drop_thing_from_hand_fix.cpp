//
// Created by DiaLight on 27.10.2024.
//

#include <sstream>
#include <iostream>
#include "drop_thing_from_hand_fix.h"
#include "dk2/entities/entities_type.h"
#include "dk2/entities/CObject.h"
#include "dk2_globals.h"
#include <vector>
#include <deque>

bool drop_thing_from_hand_fix::enabled = true;

namespace drop_thing_from_hand_fix {
    struct PlayerFix {
        std::deque<uint16_t> pendingToDropThings;

        bool hasPendingToDrop() const {
            return !pendingToDropThings.empty();
        }
        void clearPendingToDrop() {
            pendingToDropThings.clear();
        }
        bool isPendingToDrop(uint16_t tagId) {
            for (auto tag: pendingToDropThings) {
                if(tag == tagId) return true;
            }
            return false;
        }
        uint16_t popPendingToDrop() {
            uint16_t tagId = pendingToDropThings.front();
            pendingToDropThings.pop_front();
            return tagId;
        }
    };
    PlayerFix players[7];
}

void drop_thing_from_hand_fix::init(dk2::CPlayer *player) {
    auto &extraPlayerData = players[player->playerNumber];
    extraPlayerData.clearPendingToDrop();
}

void drop_thing_from_hand_fix::modifyCheckIdx(dk2::CDefaultPlayerInterface *dplif, dk2::CPlayer *player, int &thingInHandIdx) {
    auto &fix = players[player->playerNumber];
    while(thingInHandIdx >= 0) {
        auto tagId = player->thingsInHand[thingInHandIdx];
        bool alreadyDropped = fix.isPendingToDrop(tagId);
        if(!alreadyDropped) {
            for (int i = 0; i < dplif->thingsInHand_count; ++i) {
                auto &tih = dplif->thingsInHand[i];
                if(tih.tagId != tagId) continue;
                if (!tih.dropped) continue;
                alreadyDropped = true;
                break;
            }
        }
        if(!alreadyDropped) return;
        thingInHandIdx--;
//        printf("force dont drop2 %d\n", fix.pendingToDropThings);
    }
}

uint16_t drop_thing_from_hand_fix::popThingFromHand(dk2::CPlayer *player) {
    auto &fix = players[player->playerNumber];

    // if thingsInHand contains pending item, then select it to drop
    uint16_t resultTag = 0;
    while(fix.hasPendingToDrop()) {
        uint16_t candidateTag = fix.popPendingToDrop();
        for (int i = player->thingsInHand_count - 1; i >= 0; --i) {
            uint16_t tagId = player->thingsInHand[i];
            if (candidateTag != tagId) continue;
            resultTag = tagId;
            memcpy(&player->thingsInHand[i], &player->thingsInHand[i + 1], ((player->thingsInHand_count - 1) - i) * sizeof(uint16_t));
            break;
        }
        if(resultTag != 0) break;
    }
    // if there is no pending item, but we have not empty thingsInHand, use default behaviour
    if(resultTag == 0) {
        resultTag = player->thingsInHand[player->thingsInHand_count - 1];
    }

    // we must clear pending tags that not in thingsInHang to be able to generate drop events for them
    std::vector<uint16_t> absentTags;
    for (auto pendingTagId: fix.pendingToDropThings) {
        bool found = false;
        for (int i = 0; i < player->thingsInHand_count; ++i) {
            uint16_t tagId = player->thingsInHand[i];
            if(pendingTagId != tagId) break;
            found = true;
            break;
        }
        if(!found) {
            printf("sync failed tagId=%04X\n", pendingTagId);
            absentTags.push_back(pendingTagId);
        }
    }
    for (auto absentTag : absentTags) {
        auto it = std::find(fix.pendingToDropThings.begin(), fix.pendingToDropThings.end(), absentTag);
        fix.pendingToDropThings.erase(it);
    }
    return resultTag;
}

void drop_thing_from_hand_fix::onPushDropThing(dk2::CPlayer *player, uint16_t tagId) {
    auto &fix = players[player->playerNumber];
    fix.pendingToDropThings.push_back(tagId);
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
           fix.pendingToDropThings.size());
    if(thingInHand->fE_type == CThing_type_CObject) {
        dk2::CObject *object = (dk2::CObject *) thingInHand;
        printf(" obj.ty=%s", CObject_typeId_toString(object->typeId));
    }
    printf("\n");
}
