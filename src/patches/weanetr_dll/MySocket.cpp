//
// Created by DiaLight on 20.12.2024.
//

#include <WinSock2.h>
#include "MySocket.h"
#include "logging.h"

using namespace net;

void __stdcall MySocket_close(MySocket *sock) {
    if ( sock->socket != -1 ) ::closesocket(sock->socket);
}

void __cdecl MySocket_fromSockAddr(struct sockaddr_in *sockddr, MySocket *outSock) {
    *outSock = {0, NULL, 0};
    outSock->portBe = sockddr->sin_port;
    outSock->ipv4 = sockddr->sin_addr.S_un.S_addr;
}

int __stdcall MySocket_recv(void *buf, int len, MySocket *dst, MySocket *src) {
    struct sockaddr from;
    int fromlen = sizeof(sockaddr);
    int size = ::recvfrom(dst->socket, (char *)buf, len, 0, &from, &fromlen);
    if (size != -1 ) {
        MySocket_fromSockAddr((struct sockaddr_in *) &from, src);
    }
    return size;
}

void __cdecl MySocket_toSockAddr(MySocket *sock, struct sockaddr_in *outAddr) {
    ZeroMemory(outAddr, sizeof(*outAddr));
    outAddr->sin_family = 2;
    outAddr->sin_port = sock->portBe;
    outAddr->sin_addr.S_un.S_addr = sock->ipv4;
}

int __stdcall MySocket_send(MySocket *src, MySocket *dst, void *buf, size_t len) {
    struct sockaddr_in addr;
    MySocket_toSockAddr(dst, &addr);
    int size = ::sendto(
            src->socket,
            (const char *) buf, len,
            0,
            (const struct sockaddr *) &addr, sizeof(addr)
    );
    if (size == -1 )
        _log("\t\t\tSOCKET ERROR SEND \n");
    return size;
}
