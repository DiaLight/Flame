//
// Created by DiaLight on 01.10.2024.
//

#ifndef FLAME_ROOM_TYPE_H
#define FLAME_ROOM_TYPE_H

#define CRoom_types(cb) \
    cb(1, Treasury)\
    cb(2, unk_2)\
    cb(3, Entrance)\
    cb(4, Hatchery)\
    cb(5, DungeonHeart)\
    cb(6, Library)\
    cb(7, unk_7)\
    cb(8, WoodenBridge)  /* _DWORD  field_49_union_start: FlagToBurn */\
    cb(9, GuardPost)\
    cb(10, Workshop)\
    cb(11, Prison)\
    cb(12, TortureRoom)\
    cb(13, Temple)\
    cb(14, Graveyard)\
    cb(15, Casino)\
    cb(16, CombatPit)\
    cb(17, _StoneBridge)  /* _DWORD  field_49_union_start: FlagToBurn*/\
    cb(18, unk_18)\
    cb(19, unk_19)\
    cb(20, unk_20)\
    cb(21, HeroGateFrontEnd)\
    cb(22, unk_22)\
    cb(23, unk_23)\
    cb(24, MercenaryGate)\
    cb(25, HeroPortal)\
    cb(26, Crypt)


enum CRoom_typeId {
#define _CRoom_typeId(id, pascalName) CRoom_typeId_##pascalName = id,
    CRoom_types(_CRoom_typeId)
};
const char *CRoom_typeId_toString(int ty);

#endif //FLAME_ROOM_TYPE_H
