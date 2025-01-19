//
// Created by DiaLight on 20.12.2024.
//

#ifndef FLAME_MYSOCKET_H
#define FLAME_MYSOCKET_H

#include <Windows.h>

namespace net {

#pragma pack(push, 1)
class MySocket {
public:
    u_short portBe = 0;
    SOCKET socket = NULL;
    DWORD ipv4 = 0;
};
#pragma pack(pop)
static_assert(sizeof(MySocket) == 0xA);

void __stdcall MySocket_close(MySocket *sock);

void __cdecl MySocket_fromSockAddr(struct sockaddr_in *sockddr, MySocket *outSock);
int __stdcall MySocket_recv(void *buf, int len, MySocket *dst, MySocket *src);

void __cdecl MySocket_toSockAddr(MySocket *sock, struct sockaddr_in *outAddr);
int __stdcall MySocket_send(MySocket *src, MySocket *dst, void *buf, size_t len);

}

#endif //FLAME_MYSOCKET_H
