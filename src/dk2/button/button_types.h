//
// Created by DiaLight on 22.08.2024.
//

#ifndef FLAME_BUTTON_TYPES_H
#define FLAME_BUTTON_TYPES_H


#define CButton_types(cb)\
    cb(0, ClickButton)\
    cb(1, RadioButton)\
    cb(2, VerticalSlider)\
    cb(3, HorizontalSlider)\
    cb(4, DragButton)\
    cb(5, HoldButton)\
    cb(6, CheckBoxButton)\
    cb(7, TextBox)\
    cb(8, TextInput)\
    cb(9, SpinButton)\
    cb(0xA, ListBox)\
    cb(0xB, ProgressBar)\
    cb(0xC, ClickTextButton)


enum CButtonType {
#define _CButton_typeId(id, pascalName) BT_C##pascalName = id,
    CButton_types(_CButton_typeId)
};
const char *CButtonType_toString(int ty);

#endif //FLAME_BUTTON_TYPES_H
