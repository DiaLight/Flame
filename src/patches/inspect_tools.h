//
// Created by DiaLight on 19.01.2025.
//

#ifndef FLAME_INSPECT_TOOLS_H
#define FLAME_INSPECT_TOOLS_H

#include <Windows.h>

namespace dk2 {

    class CDefaultPlayerInterface;

}

namespace net {

    class MySocket;

}


namespace patch::inspect_tools {

    extern bool enable;

    void sockBind(SOCKET hSock, ULONG ipv4);
    void sockSend(void *buf, int len, net::MySocket *dst, net::MySocket *src);
    void sockRecv(void *buf, int len, net::MySocket *dst, net::MySocket *src);

    void init();

}


#endif //FLAME_INSPECT_TOOLS_H
