//
// Created by DiaLight on 7/28/2025.
//

#ifndef AUTO_NETWORK_H
#define AUTO_NETWORK_H

namespace dk2 {
    struct CFrontEndComponent;
}

namespace patch::auto_network {
    extern bool enabled;
    bool main(dk2::CFrontEndComponent *front);
    void onSessionsUpdated(dk2::CFrontEndComponent *front);
}

#endif //AUTO_NETWORK_H
