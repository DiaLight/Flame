//
// Created by DiaLight on 18.12.2024.
//

#ifndef FLAME_DNSRESOLVER_H
#define FLAME_DNSRESOLVER_H

#include <Windows.h>
#include "structs.h"

namespace net {

//static_assert(sizeof(WSADATA) == 0x18E);
static_assert(sizeof(WSADATA) == 0x190);

#pragma pack(push, 1)
class DnsResolver {
public:
    WSADATA f0_wsaData;
    char f18E_hostname[255];
    int f28D_ipv4_eos;

    DnsResolver() {}
    ~DnsResolver() {
        f28D_ipv4_eos = 0;
    }

    int wsaStartup();
    int resolve(const char *a2_hostname);
    int connect(MySocket *a2_sock, int ipv4);

private:
    int _connect(MySocket *a2_sock, int ipv4);

};
#pragma pack(pop)
//static_assert(sizeof(DnsResolver) == 0x291);
static_assert(sizeof(DnsResolver) == 0x293);

}  // namespace net

#endif //FLAME_DNSRESOLVER_H
