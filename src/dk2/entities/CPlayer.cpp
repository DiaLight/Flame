//
// Created by DiaLight on 08.08.2024.
//
#include "dk2/entities/CPlayer.h"
#include "dk2/entities/CCreature.h"
#include "dk2/CWorld.h"
#include "dk2/entities/CRoom.h"
#include "dk2/entities/data/MyObjectDataObj.h"
#include "dk2_globals.h"
#include "patches/micro_patches.h"


BOOL dk2::MyManufactureList::testManufactureCompleted(unsigned __int16 a2_completed) {
    if (!this->numberOfUsedItems) return FALSE;
    if(workshop_manufacture_build_time_fix::enabled) {
        return a2_completed >= (unsigned int) this->items[this->startIndex].manufactureRequired;
    }
    return a2_completed >= (unsigned int) this->items[0].manufactureRequired;
}

int dk2::MyManufactureList::getPercentCompleted(unsigned __int16 a2_completed) {
    if (!this->numberOfUsedItems) return 0;
    if(workshop_manufacture_build_time_fix::enabled) {
        return 100 * a2_completed / (unsigned __int16) this->items[this->startIndex].manufactureRequired;
    }
    return 100 * a2_completed / (unsigned __int16) this->items[0].manufactureRequired;
}

int dk2::CPlayer::creatureDidWorkshopWork(int workMade, CCreature *a3_creature) {
    workMade &= 0xFFFF;  // arg is uint16_t
//    printf("tickWorkshopProduction %d manufacture: (%d += %d) / %d\n", a3_creature->f0_tagId,
//           this->manufactureCompleted, productionSpeed,
//           this->manufactures.items[this->manufactures.startIndex].manufactureRequired);
    if (this->casinoBigWinnerGameTickRemaining) {
        // potential place to speedup by casino
        g_pCWorld->getGameTick();
    }
    unsigned int GameTick = g_pCWorld->getGameTick();
    if (!(GameTick % Obj6F2550_instance.gameTick)) a3_creature->sub_4F2300(a3_creature->f24_playerId);
    int f4BB_lastSlapTick = a3_creature->lastSlapTick;
    if(f4BB_lastSlapTick) {
        if ((g_pCWorld->getGameTick() - f4BB_lastSlapTick) <
            ((unsigned int) Obj6F2550_instance.f3EA * Obj6F2550_instance.gameTick)) {
            // potential place to speedup by slapping
            g_pCWorld->getGameTick();
        }
    }
    this->manufactureCompleted += workMade;
    if (!this->manufactures.testManufactureCompleted(this->manufactureCompleted)) return 0;

    MyManufactureItem a3a_item;
    memset(&a3a_item.pos, 0, sizeof(a3a_item.pos));
    this->manufactures.getItem(&a3a_item);
    uint8_t typeId = this->manufactures.sub_506BA0(&a3a_item);
    MyObjectDataObj *v7 = g_pCWorld->v_findMyObjectDataObjByTypeId_50DB20(typeId);
    CRoom *room;
    if (!this->sub_4C3B50(&a3a_item, 10, v7->f114, &room)) return 0;
    this->manufactureCompleted = 0;
    this->manufactures.popItem(&a3a_item);
    if (room->spawnBuiltManufactureItem(&a3a_item, a3_creature) == 0) return 0;
    return 1;
}
