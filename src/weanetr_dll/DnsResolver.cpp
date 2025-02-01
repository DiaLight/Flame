//
// Created by DiaLight on 18.12.2024.
//

#include "DnsResolver.h"
#include "logging.h"
#include "patches/micro_patches.h"

using namespace net;

int DnsResolver::wsaStartup() {
    return WSAStartup(MAKEWORD(1, 1), &this->f0_wsaData);
}

int DnsResolver::resolve(const char *a2_hostname) {
    ULONG ipv4 = 0;
    strcpy(this->f18E_hostname, a2_hostname);
    struct hostent *hostent = gethostbyname(this->f18E_hostname);

    if ( hostent ) {
        ipv4 = ((in_addr *) hostent->h_addr_list[0])->S_un.S_addr;
        patch::multi_interface_fix::replaceLocalIp(hostent, ipv4);
    }

    if ( !ipv4 ) return -1;
    return ipv4;
}

int DnsResolver::_connect(MySocket *a2_sock, int ipv4) {
    DWORD optval = 1;
    if (setsockopt(a2_sock->socket, SOL_SOCKET, SO_BROADCAST, (char *) &optval, 4) == -1) return false;
    struct sockaddr_in _sockaddr;
    memset(&_sockaddr.sin_port, 0, 14);
    _sockaddr.sin_family = 2;
    _sockaddr.sin_port = htons(a2_sock->portBe);
    _sockaddr.sin_addr.S_un.S_addr = ipv4 ? ipv4 : htonl(0);
    if (bind(a2_sock->socket, (const struct sockaddr *) &_sockaddr, 16) != 0) return false;
    optval = 16;
    if (getsockname(a2_sock->socket, (struct sockaddr *) &_sockaddr, (int *) &optval)) return false;
    if (optval != 16) return false;
    if ( ipv4 == 0 ) {
        this->f28D_ipv4_eos = 0;
        if ( gethostname(this->f18E_hostname, sizeof(this->f18E_hostname)) == 0 ) {
            _log("\tBullfrogNET Local Host Name = %s\n", this->f18E_hostname);
            this->f28D_ipv4_eos = this->resolve(this->f18E_hostname);
        }

        a2_sock->portBe = _sockaddr.sin_port;
        a2_sock->ipv4 = this->f28D_ipv4_eos;
        if ( f28D_ipv4_eos == 0 || f28D_ipv4_eos == -1 ) return false;
        return true;
    }
    this->f28D_ipv4_eos = ipv4;
    if (ipv4 == -1) return false;
    a2_sock->portBe = _sockaddr.sin_port;
    a2_sock->ipv4 = this->f28D_ipv4_eos;
    return true;
}
int DnsResolver::connect(MySocket *a2_sock, int ipv4) {
    SOCKET v4_socket = socket(2, 2, 0);  // AF_INET, SOCK_DGRAM, IPPROTO_IP
    a2_sock->socket = v4_socket;
    if ( v4_socket == -1 ) return 255;
    if (!_connect(a2_sock, ipv4)) {
        closesocket(a2_sock->socket);
        return 255;
    }
    return 0;
}
