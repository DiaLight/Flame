//
// Created by DiaLight on 04.05.2025.
//

#ifndef FLAME_CCREATUREEXTENDED_H
#define FLAME_CCREATUREEXTENDED_H

#include "dk2/entities/CCreature.h"

#define UseExtendedCreature 1

#if UseExtendedCreature
namespace dk2ex {

    struct CCreatureExtended : dk2::CCreature {

        int dropSelectPenalty;

        void constructorEx();

        bool decrementDropSelectPenalty(int totalNumberOfOwnedCreatures);

        void setDropSelectPenalty(int totalNumberOfOwnedCreatures);
    };
    static_assert(sizeof(CCreatureExtended) == (sizeof(dk2::CCreature) + 5));

}
#endif


#endif //FLAME_CCREATUREEXTENDED_H
