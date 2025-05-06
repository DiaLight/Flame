//
// Created by DiaLight on 02.05.2025.
//

#include "computer_player_flags.h"
#include "dk2/MyComputerPlayer.h"


int currentEventTask_fromFlags(uint32_t flags) {
    return (flags >> 14) & 0xF;
}
uint32_t currentEventTask_toFlags(int value) {
    return (value & 0xF) << 14;
}

int getCurrentEventTask(dk2::MyComputerPlayer *cp) {
    return currentEventTask_fromFlags(cp->flags);
}

int numberOfEventTasks_fromFlags(uint32_t flags) {
    return (flags >> 18) & 0xF;
}
uint32_t numberOfEventTasks_toFlags(int value) {
    return (value & 0xF) << 18;
}

int getNumberOfEventTasks(dk2::MyComputerPlayer *cp) {
    return numberOfEventTasks_fromFlags(cp->flags);
}


int task_fromFlags(uint32_t flags) {
    return (flags >> 22) & 0xF;
}
uint32_t task_toFlags(int value) {
    return (value & 0xF) << 22;
}

int getTask(dk2::MyComputerPlayer *cp) {
    return task_fromFlags(cp->flags);
}


int nextTask_fromFlags(uint32_t flags) {
    return (flags >> 26) & 0xF;
}
uint32_t nextTask_toFlags(int value) {
    return (value & 0xF) << 26;
}

int getNextTask(dk2::MyComputerPlayer *cp) {
    return task_fromFlags(cp->flags);
}


int probabilityOfMovingCreatureForResearch_fromFlags(uint32_t flags) {
    return (flags >> 17) & 3;
}
uint32_t probabilityOfMovingCreatureForResearch_toFlags(int value) {
    return (value & 3) << 17;
}
int getProbabilityOfMovingCreatureForResearch(dk2::MyComputerPlayer *cp) {
    return probabilityOfMovingCreatureForResearch_fromFlags(cp->buildFlags);
}


