//
// Created by DiaLight on 08.08.2024.
//
#include "entities_type.h"

const char *CCreature_typeId_toString(int ty) {
    switch (ty) {
#define _CCreature_typeId_toString(id, isEvil, pascalName, snakeName) case CCreature_typeId_##pascalName: return #pascalName;
        CCreature_types(_CCreature_typeId_toString)
    }
    return "Unknown";
}

const char *CObject_typeId_toString(int ty) {
    switch (ty) {
#define _CObject_typeId_toString(id, pascalName) case CObject_typeId_##pascalName: return #pascalName;
        CObject_types(_CObject_typeId_toString)
    }
    return "Unknown";
}
