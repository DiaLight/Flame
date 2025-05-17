//
// Created by DiaLight on 19.01.2025.
//

#include "inspect_tools.h"
#include "dk2_globals.h"
#include <sstream>
#include <dk2/gui/visual_debug.h>
#include <tools/flame_config.h>

#include "dk2/entities/entities_type.h"
#include "dk2/entities/CObject.h"
#include "dk2/entities/CPlayer.h"
#include "dk2/MyComputerPlayer.h"
#include "tools/command_line.h"
#include "dk2_functions.h"
#include "weanetr_dll/protocol.h"
#include "weanetr_dll/MySocket.h"
#include "patches/logging.h"

#define fmtHex(val) std::hex << std::uppercase << (val) << std::dec

bool patch::inspect_tools::enable = false;

flame_config::define_flame_option<bool> o_inspect(
    "flame:inspect",
    "Some debug info. Used in development\n",
    false
);

void patch::inspect_tools::init() {
    inspect_tools::enable = o_inspect.get();
    if(!inspect_tools::enable) return;
    printf("Flame inspect tools enabled\n");
}

void patch::inspect_tools::onMouseAction(dk2::CDefaultPlayerInterface *dplif) {
    if(!inspect_tools::enable || true) return;
    int x = 0;
    int y = 0;
    uint16_t whoGets = 0;
    uint16_t chickPl = 0;
    if(dk2::sceneObjectsPresent[0x98D]) {
        dk2::CObject *chick = (dk2::CObject *) dk2::sceneObjects[0x98D];
        x = chick->f16_pos.x;
        y = chick->f16_pos.y;
        whoGets = chick->whoGetsThisFromADrop;
        chickPl = chick->f24_playerId;
    }
    printf("left click [%.2f %.2f] tag=%X  pl=%X   [%.2f %.2f] %X\n",
           dplif->_underHand.x_if12 / 2048.0,
           dplif->_underHand.y_if12 / 2048.0,
           dplif->_underHand.tagId,
           dplif->playerTagId,
           x / 2048.0, y / 2048.0, whoGets
    );
    if(chickPl) {
        dk2::CPlayer *pl = (dk2::CPlayer *) dk2::sceneObjects[chickPl];
        std::stringstream ss;
        for (int i = 0; i < pl->thingsInHand_count; ++i) {
            if(i != 0) ss << ", ";
            uint16_t tag = pl->thingsInHand[i];
            dk2::CThing *pThing = (dk2::CThing *) dk2::sceneObjects[tag];
            if(pThing->fE_type == CThing_type_CObject) {
                dk2::CObject *pObj = (dk2::CObject *) pThing;
                ss << fmtHex(tag) << "(" << CObject_typeId_toString(pObj->typeId) << ")";
            } else {
                ss << fmtHex(tag) << "(" << CThing_type_toString(pThing->fE_type) << ")";
            }
        }
        printf("[%s]\n", ss.str().c_str());
    }
}

void patch::inspect_tools::windowProc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    if(!inspect_tools::enable || true) return;
    switch(Msg) {
        case WM_KEYDOWN: {
            switch (wParam) {
                case VK_UP: {
                    // auto *world = dk2::g_pCWorld;
                    // for (
                    //         dk2::CPlayer *player = (dk2::CPlayer *) dk2::sceneObjects[world->playerList.allocatedList];
                    //         player; player = (dk2::CPlayer *)dk2::sceneObjects[player->nextIdx]
                    // ) {
                    //     if(player->computerPlayerOn) {
                    //         auto *cp = player->pComputerPlayer;
                    //         printf("%d: %04X\n", player->f0_tagId, cp->flagsFFFF);
                    //     }
                    // }

                    // int textId = 218;
                    // uint8_t *MbString = (uint8_t *) dk2::MyMbStringList_idx1091_getMbString(textId);
                    // uint8_t *MbString = (uint8_t *) dk2::MyMbStringList_idx1090_getMbString(textId);
                    // uint8_t *MbString = (uint8_t *) dk2::MyMbStringList_getMbString_idx1000_1023(textId);
                    // wchar_t text[256] = {0};
                    // dk2::MBToUni_convert(MbString, text, 256);
                    // printf("%d: %S\n", textId, text);
                    // {
                    //     auto &gui = dk2::CFrontEndComponent_instance.cgui_manager;
                    //     for (auto w = gui.windowListEnd.f5E_next; w; w = w->f5E_next) {
                    //         if (w->f44_isCurrent) {
                    //             printf("FrEnd cur: id=0x%X\n", w->f40_id);
                    //         }
                    //     }
                    // }
                    // {
                    //     auto &gui = dk2::CDefaultPlayerInterface_instance.cgui_manager;
                    //     for (auto w = gui.windowListEnd.f5E_next; w; w = w->f5E_next) {
                    //         if (!w->f44_isCurrent) continue;
                    //         if(w->f40_id == 0x4) continue;
                    //         if(w->f40_id == 0x6) continue;
                    //         if(w->f40_id == 0x7) continue;
                    //         if(w->f40_id == 0x12) continue;
                    //         if(w->f40_id == 0x14) continue;
                    //         if(w->f40_id == 0x15) continue;
                    //         if(w->f40_id == 0x27) continue;
                    //         if(w->f40_id == 0x29) continue;
                    //         if(w->f40_id == 0x2B) continue;
                    //         if(w->f40_id == 0x2D) continue;
                    //         if(w->f40_id == 0x35) continue;
                    //         printf("DPlIf cur: id=0x%X\n", w->f40_id);
                    //     }
                    // }
                } break;
                case VK_RIGHT: {
                    auto *surf = dk2::MyResources_loadPng("unk");
                    dump(*surf);
                } break;
                case VK_DOWN: {
                    auto &gui = dk2::CFrontEndComponent_instance.cgui_manager;

                    dk2::CFrontEndComponent_instance.fillGuiDisplayStrings();

                    for (auto w = gui.windowListEnd.f5E_next; w; w = w->f5E_next) {
                        w->f44_isCurrent = false;
                    }
                    gui.findGameWindowById(0x2E)->f44_isCurrent = 1;
                } break;
            }
            break;
        }
    }
}

void patch::inspect_tools::sockBind(SOCKET hSock, ULONG ipv4) {
    if (!patch::inspect_tools::enable) return;
    patch::log::sock("sock bind %X-%d.%d.%d.%d",
                     hSock,
                     ipv4 & 0xFF, (ipv4 >> 8) & 0xFF, (ipv4 >> 16) & 0xFF,
                     (ipv4 >> 24) & 0xFF
    );
}
void patch::inspect_tools::sockSend(void *buf, int len, net::MySocket *dst, net::MySocket *src) {
    if (!patch::inspect_tools::enable) return;
    auto pkt = (net::PacketHeader *) buf;
    if (
            pkt->packetTy != net::MyPacket_D_Guaranteed::ID
            && pkt->packetTy != net::MyPacket_10_GuaranteedProgress::ID
//            && pkt->packetTy != net::MyPacket_3_Data::ID
    ) return;
    if(pkt->packetTy == net::MyPacket_3_Data::ID) {
        auto data = (net::MyPacket_3_Data *) pkt;
        patch::log::sock("send data dty=%X sz=%X %X-%d.%d.%d.%d -> %X-%d.%d.%d.%d",
                         (uint32_t) data->fC_data[0], len,
                         src->socket,
                         src->ipv4 & 0xFF, (src->ipv4 >> 8) & 0xFF, (src->ipv4 >> 16) & 0xFF,
                         (src->ipv4 >> 24) & 0xFF,
                         dst->socket,
                         dst->ipv4 & 0xFF, (dst->ipv4 >> 8) & 0xFF, (dst->ipv4 >> 16) & 0xFF,
                         (dst->ipv4 >> 24) & 0xFF
        );
    } else {
        patch::log::sock("send ty=%X sz=%X %X-%d.%d.%d.%d -> %X-%d.%d.%d.%d",
                         (uint32_t) pkt->packetTy, len,
                         src->socket,
                         src->ipv4 & 0xFF, (src->ipv4 >> 8) & 0xFF, (src->ipv4 >> 16) & 0xFF,
                         (src->ipv4 >> 24) & 0xFF,
                         dst->socket,
                         dst->ipv4 & 0xFF, (dst->ipv4 >> 8) & 0xFF, (dst->ipv4 >> 16) & 0xFF,
                         (dst->ipv4 >> 24) & 0xFF
        );
    }

}
void patch::inspect_tools::sockRecv(void *buf, int len, net::MySocket *dst, net::MySocket *src) {
    if (!patch::inspect_tools::enable) return;
    auto pkt = (net::PacketHeader *) buf;
    if (
            pkt->packetTy != net::MyPacket_D_Guaranteed::ID
            && pkt->packetTy != net::MyPacket_10_GuaranteedProgress::ID
//            && pkt->packetTy != net::MyPacket_3_Data::ID
    ) return;
    if(pkt->packetTy == net::MyPacket_3_Data::ID) {
        auto data = (net::MyPacket_3_Data *) pkt;
        patch::log::sock("recv data dty=%X sz=%X %X-%d.%d.%d.%d <- %X-%d.%d.%d.%d",
                         (uint32_t) data->fC_data[0], len,
                         dst->socket,
                         dst->ipv4 & 0xFF, (dst->ipv4 >> 8) & 0xFF, (dst->ipv4 >> 16) & 0xFF,
                         (dst->ipv4 >> 24) & 0xFF,
                         src->socket,
                         src->ipv4 & 0xFF, (src->ipv4 >> 8) & 0xFF, (src->ipv4 >> 16) & 0xFF,
                         (src->ipv4 >> 24) & 0xFF
        );
    } else {
        patch::log::sock("recv ty=%X sz=%X %X-%d.%d.%d.%d <- %X-%d.%d.%d.%d",
                         (uint32_t) pkt->packetTy, len,
                         dst->socket,
                         dst->ipv4 & 0xFF, (dst->ipv4 >> 8) & 0xFF, (dst->ipv4 >> 16) & 0xFF,
                         (dst->ipv4 >> 24) & 0xFF,
                         src->socket,
                         src->ipv4 & 0xFF, (src->ipv4 >> 8) & 0xFF, (src->ipv4 >> 16) & 0xFF,
                         (src->ipv4 >> 24) & 0xFF
        );
    }

}

