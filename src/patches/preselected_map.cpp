#include <dk2/components/CFrontEndComponent.h>
#include <dk2/MyMapInfo.h>
#include <dk2_functions.h>
#include <dk2_globals.h>
#include <patches/preselected_map.h>
#include <patches/logging.h>
#include <tools/flame_config.h>

#include <cwchar>
#include <string>

flame_config::define_flame_option<std::string> o_preselected_map(
        "flame:preselected-map", flame_config::OG_Config,
        "Map preselected in skirmish and when hosting a multiplayer game.\n"
        "Empty = original behaviour.\n",
        ""
);

namespace {

    // strip path and ".kwd"
    std::wstring baseName(const wchar_t *full) {
        const wchar_t *start = full;
        for (const wchar_t *c = full; *c; ++c) {
            if (*c == L'\\' || *c == L'/') start = c + 1;
        }
        std::wstring s(start);
        if (s.size() > 4 && _wcsicmp(s.c_str() + s.size() - 4, L".kwd") == 0) s.resize(s.size() - 4);
        return s;
    }

    // exact match, else next map after target, else first map
    int findMap(dk2::CFrontEndComponent *front, const std::wstring &target) {
        int next = -1, first = -1;
        std::wstring nextName, firstName;
        for (int i = 0; i < front->mapsCount; ++i) {
            std::wstring name = baseName(front->mapInfoArr[i].name);
            int cmp = _wcsicmp(name.c_str(), target.c_str());
            if (cmp == 0) return i;
            if (cmp > 0 && (next == -1 || _wcsicmp(name.c_str(), nextName.c_str()) < 0)) {
                next = i;
                nextName = name;
            }
            if (first == -1 || _wcsicmp(name.c_str(), firstName.c_str()) < 0) {
                first = i;
                firstName = name;
            }
        }
        return next != -1 ? next : first;
    }

}

bool patch::default_map::enabled = true;

int patch::default_map::getPreselectedMapIdx(dk2::CFrontEndComponent *front) {
    const std::string &cfg = *o_preselected_map;
    if (cfg.empty() || front->mapsCount <= 0) return -1;

    int idx = findMap(front, std::wstring(cfg.begin(), cfg.end()));
    if (idx < 0) return -1;
    patch::log::dbg("(preselected map) %ls", front->mapInfoArr[idx].name);
    return idx;
}