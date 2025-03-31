//
// Created by DiaLight on 22.08.2024.
//

#include "button_types.h"

const char *CButtonType_toString(int ty) {
    switch (ty) {
#define _CButton_typeId_toString(id, pascalName) case BT_C##pascalName: return #pascalName;
        CButton_types(_CButton_typeId_toString)
    }
    return "Unknown";
}
