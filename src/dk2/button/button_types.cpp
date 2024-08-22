//
// Created by DiaLight on 22.08.2024.
//

#include "button_types.h"

const char *CButton_typeId_toString(int ty) {
    switch (ty) {
#define _CButton_typeId_toString(id, pascalName) case CButton_typeId_##pascalName: return #pascalName;
        CButton_types(_CButton_typeId_toString)
    }
    return "Unknown";
}
