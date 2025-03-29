//
// Created by DiaLight on 3/29/2025.
//

#include <dk2_functions.h>
#include <dk2_globals.h>
#include <dk2/dk2_memory.h>
#include <dk2/NameCfg.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/gui/CGuiManager.h>


namespace {
    dk2::NameCfg nameList_replace[]{
        {0, "", 1, 0, 0},
        {1, "GUI_BUTTON_TAB_ROOMS", 0, 0x104, 0x136},
        {2, "GUI_BUTTON_TAB_SPELLS", 0, 0x104, 0x136},
        {3, "GUI_BUTTON_TAB_WORKSHOP", 0, 0x104, 0x136},
        {4, "GUI_BUTTON_TAB_CREATURE", 0, 0x104, 0x136},
        {5, "GUI_BUTTON_ICON", 0, 0x104, 0x136},
        {6, "GUI_BUTTON_ICON_LARGE", 0, 0x104, 0x136},
        {7, "GUI_BUTTON_SIZE", 0, 0x104, 0},
        {8, "GUI_BUTTON_INFO", 0, 0x104, 0x136},
        {9, "GUI_SELL", 0, 0x104, 0x136},
        {0x0A, "GUI_BUTTON_OPTIONS", 0, 0x104, 0x136},
        {0x0B, "GUI_BUTTON_ZOOM", 0, 0x104, 0x136},
        {0x0C, "GUI_MINIMAP", 0, 0x104, 0x136},
        {0x0D, "GUI_MESSAGE_BAR", 0, 0, 0},
        {0x0E, "GUI_BUTTON_DEFAULT", 0, 0x104, 0x136},
        {0x0F, "GUI_BUTTON_TAB_NEW_COMBAT", 0, 0, 0},
        {0x10, "OPTIONS", 0, 0x304, 0x305},
        {0x11, "OPTIONS", 0, 0x306, 0},
        {0x12, "OPTIONS", 0, 0x307, 0},
        {0x13, "OPTIONS", 0, 0x308, 0},
        {0x14, "OPTIONS", 0, 0x309, 0},
        {0x15, "OPTIONS", 0, 0x30A, 0},
        {0x16, "OPTIONS", 0, 0x30B, 0},
        {0x17, "OPTIONS", 0, 0x30D, 0},
        {0x18, "OPTIONS", 0, 0x30E, 0},
        {0x19, "OPTIONS", 0, 0x341, 0},
        {0x1A, "OPTIONS", 0, 0x33C, 0},
        {0x1B, "OBJECT_FE_PARCHMENT", 0, 0x304, 0x305},
        {0x1C, "OBJECT_FE_PARCHMENT", 0, 0x306, 0},
        {0x1D, "OBJECT_FE_PARCHMENT", 0, 0x307, 0},
        {0x1E, "OBJECT_FE_PARCHMENT", 0, 0x308, 0},
        {0x1F, "OBJECT_FE_PARCHMENT", 0, 0x309, 0},
        {0x20, "FRONT_END", 0, 0x30A, 0},
        {0x21, "OBJECT_FE_PARCHMENT", 0, 0x30B, 0},
        {0x22, "OBJECT_FE_PARCHMENT", 0, 0x30C, 0},
        {0x23, "OBJECT_FE_PARCHMENT", 0, 0x30D, 0},
        {0x24, "OBJECT_FE_PARCHMENT", 0, 0x30E, 0},
        {-1, "", 0, 0, 0},
    };
}

void __stdcall dk2::createPanelButtons(
    CWindow *a1_win,
    CButton *a2_subBtn,
    ButtonCfg *a3_btnCfg,
    CDefaultPlayerInterface *a4_plif) {
    if (!a1_win->f24_getPanelItemsCount) return;
    int panelItemsCount = a1_win->f24_getPanelItemsCount(a1_win, 0, (CFrontEndComponent*) a4_plif);

    AABB a2a;
    AABB *ScreenPos = a1_win->getScreenPos(&a2a);
    int height = ScreenPos->maxY - ScreenPos->minY;
    int width = ScreenPos->maxX - ScreenPos->minX;

    // int items = (height * width) >> 14;
    int items = (height * width) / 0x4000;
    if (panelItemsCount < items) items = panelItemsCount;
    if (items < 2) return;

    ButtonCfg lcfg = *a3_btnCfg;
    for (int i = 0; i < items - 1; ++i) {
        ++lcfg.clickHandler_arg1;
        a2_subBtn = CButton_create(a1_win, &lcfg, a2_subBtn);
    }
}


int dk2::CGuiManager::createElements(WindowCfg **ppCurWinCfg, CDefaultPlayerInterface *a3_defPlayerI) {
    this->width = MyGame_instance.dwWidth;
    this->height = MyGame_instance.dwHeight;
    this->pWindow_first = &this->windowListEnd;
    this->pbtn_A0 = NULL;
    this->f24 = 0;
    this->aabb.minX = 0;
    this->aabb.minY = 0;
    this->aabb.maxX = 640;
    this->aabb.maxY = 480;
    for (; (*ppCurWinCfg)->idx != -1; ++ppCurWinCfg) {
        WindowCfg &curWinCfg = **ppCurWinCfg;

        CWindow *win = (CWindow*) dk2::operator_new(sizeof(CWindow));
        if (win) win = win->constructor();
        if (!win) continue;

        this->pWindow_first->f5E_next = win;
        win->f5A_prev = this->pWindow_first;
        this->pWindow_first = win;
        win->configure(&curWinCfg, this);
        if (!curWinCfg.pButtonCfg_list) {
            win->f66_buttons = NULL;
            continue;
        }
        CButton *lastBtnInList = NULL;
        ButtonCfg *lastBtnCfg = NULL;
        for (ButtonCfg *curBtnCfg = curWinCfg.pButtonCfg_list; curBtnCfg->idx != -1; curBtnCfg++) {
            lastBtnInList = CButton_create(win, curBtnCfg, lastBtnInList);
            lastBtnCfg = curBtnCfg;
        }
        if ((curWinCfg.flags & 1) != 0) {
            createPanelButtons(win, lastBtnInList, lastBtnCfg, a3_defPlayerI);
        }
    }
    this->strlen = 0;
    this->f10 = 0;
    this->f14 = 0;
    this->f18 = 0;
    this->f1C = 0;
    this->f20 = 0;
    this->pBtn = NULL;
    this->is_clicked = 0;
    this->fC0 = 0;
    this->fC4 = 0;
    this->fC8 = 0;
    NameCfg *entry = ::nameList_replace;
    if (nameList[0].f24 != 1)
        return 1;
    if (nameList[0].idx != -1) {
        int idx;
        do {
            if (entry->idx < 27)
                entry->f24 = MySound_ptr->v_fun_567790("GLOBAL\\", entry->str);
            idx = entry[1].idx;
            ++entry;
        } while (idx != -1);
    }
    nameList[0].f24 = 0;
    return 1;
}
