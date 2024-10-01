//
// Created by DiaLight on 01.10.2024.
//
#include "dk2/button/CTextInput.h"
#include "dk2/button/ButtonCfg.h"
#include "dk2_functions.h"
#include "dk2_globals.h"
#include "patches/micro_patches.h"


int dk2::CTextInput::fun_52AA10_configure(ButtonCfg *a2_cfg) {
    void *v2_strId = a2_cfg->var16;
    if (v2_strId) {
        unsigned __int8 *MbString = MyMbStringList_idx1091_getMbString((unsigned int) v2_strId);
        MBToUni_convert(MbString, this->str2, 128);
    } else {
        this->str2[0] = 0;
    }
    int f1A_inputLimit = (int) a2_cfg->var1A;
    if (f1A_inputLimit == -1) {
        if (MyResources_instance.playerCfg.kbLayoutId == 17)
            this->f27C_inputLimit = 11;
        else
            this->f27C_inputLimit = 16;
    } else {
        if(max_host_port_number_fix::enabled) {
            if(this->f70_idx == 0x212) {  // port number
                f1A_inputLimit++;
            }
        }
        this->f27C_inputLimit = f1A_inputLimit;
    }
    this->field_280 = 0;
    this->field_284 = (unsigned __int16) a2_cfg->idxHigh == 1;
    memset(this->str1, 0, sizeof(this->str1));
    this->field_288 = ((int) a2_cfg->idxHigh & 0xFFFF0000) == 0x10000;
    return 0;
}
