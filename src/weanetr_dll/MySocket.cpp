//
// Created by DiaLight on 20.12.2024.
//

#include <WinSock2.h>
#include "MySocket.h"
#include "logging.h"
#include "protocol.h"
#include "patches/logging.h"
#include "patches/inspect_tools.h"


void __stdcall net::MySocket_close(MySocket *sock) {
    if ( sock->socket != -1 ) ::closesocket(sock->socket);
}

void __cdecl net::MySocket_fromSockAddr(struct sockaddr_in *sockddr, MySocket *outSock) {
    *outSock = {0, NULL, 0};
    outSock->portBe = sockddr->sin_port;
    outSock->ipv4 = sockddr->sin_addr.S_un.S_addr;
}

int __stdcall net::MySocket_recv(void *buf, int len, MySocket *dst, MySocket *src) {
    struct sockaddr from;
    int fromlen = sizeof(sockaddr);
    int size = ::recvfrom(dst->socket, (char *)buf, len, 0, &from, &fromlen);
    if (size != -1 ) {
        MySocket_fromSockAddr((struct sockaddr_in *) &from, src);
        patch::inspect_tools::sockRecv(buf, size, dst, src);
    }
    return size;
}

void __cdecl net::MySocket_toSockAddr(MySocket *sock, struct sockaddr_in *outAddr) {
    ZeroMemory(outAddr, sizeof(*outAddr));
    outAddr->sin_family = AF_INET;
    outAddr->sin_port = sock->portBe;
    outAddr->sin_addr.S_un.S_addr = sock->ipv4;
}

int __stdcall net::MySocket_send(MySocket *src, MySocket *dst, void *buf, size_t len) {
    patch::inspect_tools::sockSend(buf, len, dst, src);
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
