//
// Created by DiaLight on 19.01.2025.
//

#include "inspect_tools.h"
#include <tools/flame_config.h>

#include "dk2/entities/CObject.h"
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

