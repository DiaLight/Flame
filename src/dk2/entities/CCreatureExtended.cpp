//
// Created by DiaLight on 04.05.2025.
//

#include "CCreatureExtended.h"

#ifdef UseExtendedCreature

void dk2ex::CCreatureExtended::constructorEx() {
    dropSelectPenalty = 0;
}

bool dk2ex::CCreatureExtended::decrementDropSelectPenalty(int totalNumberOfOwnedCreatures) {
    if(dropSelectPenalty <= 0) return false;
    dropSelectPenalty--;
    if(dropSelectPenalty > (totalNumberOfOwnedCreatures - 1)) dropSelectPenalty = totalNumberOfOwnedCreatures - 1;
    if(dropSelectPenalty < 0) dropSelectPenalty = 0;
    return true;
}

void dk2ex::CCreatureExtended::setDropSelectPenalty(int totalNumberOfOwnedCreatures) {
    dropSelectPenalty = totalNumberOfOwnedCreatures - 1;
    if(dropSelectPenalty < 0) dropSelectPenalty = 0;
}

#endif
