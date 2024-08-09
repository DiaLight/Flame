//
// Created by DiaLight on 08.08.2024.
//

#ifndef FLAME_ENTITIES_TYPE_H
#define FLAME_ENTITIES_TYPE_H


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
const char *CCreature_typeId_toString(int ty);


#define CObject_types(cb)\
    cb(4, ResearchBook)\
    cb(8, TortureWheel)\
    cb(9, Chicken)\
    cb(10, CallToArms)\
    cb(11, Rat)\
    cb(29, TrainingTarget)\
    cb(31, TombStone)\
    cb(32, TombStone_2)\
    cb(33, TombStone_3)\
    cb(34, TombStone_4)\
    cb(35, Coop)\
    cb(52, MyWorkshopItem)\
    cb(64, BookCase)\
    cb(70, GuardPost)\
    cb(74, Boulder)\
    cb(98, Destructor)\
    cb(101, ManaVault)\
    cb(103, ThreatBurn)\
    cb(108, ClaimedManaVault)\
    cb(110, FECandleStick)\
    cb(111, TempleCandleStick)\
    cb(114, HeroGate2By2)\
    cb(0, None)

enum CObject_typeId {
#define _CObject_typeId(id, pascalName) CObject_typeId_##pascalName = id,
    CObject_types(_CObject_typeId)
};
const char *CObject_typeId_toString(int ty);

#endif //FLAME_ENTITIES_TYPE_H
