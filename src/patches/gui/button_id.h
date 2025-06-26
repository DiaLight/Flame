//
// Created by DiaLight on 6/25/2025.
//

#ifndef BUTTON_ID_H
#define BUTTON_ID_H

namespace dk2 {

    enum ButtonId {
#define Dk2BtnIdx_max 696
#define CustomBtnId_start 700

        BID_SinglePlayer_CustomCampaign = CustomBtnId_start,

        BID_CustomCampaign_Back,
        BID_CustomCampaign_Apply,

    };

}

#endif //BUTTON_ID_H
