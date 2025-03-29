//
// Created by DiaLight on 3/29/2025.
//


#include <dk2_functions.h>
#include <dk2/button/CClickButton.h>
#include <dk2/gui/CGuiManager.h>

dk2::CClickButton *dk2::CClickButton::handleClick(CDefaultPlayerInterface *a2) {
    CWindow *f51_pWindow; // eax
    CGuiManager *f4A_c_gui_manager; // ecx
    CGuiManager *v6; // eax

    f51_pWindow = this->f51_pWindow;
    f4A_c_gui_manager = f51_pWindow->f4A_c_gui_manager;
    if (f4A_c_gui_manager->fC0) {
        if (!this->f3D__isPressed) {
            if (this->f49_leftClickHandler) {
                f4A_c_gui_manager->pbtn_A0 = this;
                this->f49_leftClickHandler(this->f63_clickHandler_arg1, this->f67_clickHandler_arg2, a2);
            }
            if (this->f59__isExitOnClick)
                this->f51_pWindow->f44_isCurrent = 0;
            if (this->f55__nextWindowIdOnClick) {
                auto *nextWindow = this->f51_pWindow->f4A_c_gui_manager->findGameWindowById(this->f55__nextWindowIdOnClick);
                nextWindow->f44_isCurrent = 1;
            }
        }
        this->f3D__isPressed = 1;
        return this;
    } else {
        if (this->f3D__isPressed == 1)
            this->f3D__isPressed = 0;
        v6 = f51_pWindow->f4A_c_gui_manager;
        if (v6->fC4) {
            if (this->f4D_rightClickHandler && !this->field_41) {
                v6->pbtn_A0 = this;
                this->f4D_rightClickHandler(this->f63_clickHandler_arg1, this->f67_clickHandler_arg2, a2);
            }
            this->field_41 = 1;
            return this;
        } else {
            if (this->field_41 == 1)
                this->field_41 = 0;
            return 0;
        }
    }
}
