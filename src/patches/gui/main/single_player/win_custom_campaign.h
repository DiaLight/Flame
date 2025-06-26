//
// Created by DiaLight on 6/2/2025.
//

#ifndef WIN_CUSTOM_CAMPAIGN_H
#define WIN_CUSTOM_CAMPAIGN_H



#include <dk2/gui/WindowCfg.h>
#include <dk2/gui/ButtonCfg.h>
#include <dk2/utils/Area4s.h>

namespace patch::custom_campaign {

    extern bool enabled;

    constexpr int animEndAction = 50;

    dk2::ButtonCfg SinglePlayer_CustomCampaign_btn(dk2::Area4s a1, dk2::Area4s a2);

    dk2::WindowCfg *SinglePlayer_CustomCampaign_layout();


}



#endif //WIN_CUSTOM_CAMPAIGN_H
