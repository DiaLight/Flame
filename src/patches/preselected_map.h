#ifndef DEFAULT_MAP_H
#define DEFAULT_MAP_H

namespace dk2 {
    struct CFrontEndComponent;
}

namespace patch::default_map {
    extern bool enabled;

    int getPreselectedMapIdx(dk2::CFrontEndComponent *front);

}

#endif //DEFAULT_MAP_H