//
// Created by DiaLight on 7/28/2025.
//

#include <dk2/CFrontEndComponent.h>
#include <dk2/MyMapInfo.h>
#include <dk2/gui/main/main_layout.h>
#include <dk2_functions.h>
#include <dk2_globals.h>
#include <patches/auto_network.h>
#include <patches/logging.h>
#include <tools/flame_config.h>

#include "scheduler.h"


namespace {
    bool g_auto_network_applied = false;
    bool g_auto_network_connect_applied = false;

    std::vector<std::string> split(const std::string& s, const std::string& delimiter) {
        size_t pos_start = 0, pos_end, delim_len = delimiter.length();
        std::string token;
        std::vector<std::string> res;

        while ((pos_end = s.find(delimiter, pos_start)) != std::string::npos) {
            token = s.substr (pos_start, pos_end - pos_start);
            pos_start = pos_end + delim_len;
            res.push_back (token);
        }

        res.push_back (s.substr (pos_start));
        return res;
    }

    enum service_t {
        SV_None,
        SV_TCPIP,
        SV_IPX
    } g_service = SV_None;

    void tryAutoconnect(dk2::CFrontEndComponent *front) {
        if (g_auto_network_connect_applied) return;
        if (front->f30C1E != 0) {
            g_auto_network_connect_applied = true;
            return;  // already connected
        }
        bool hasAnySession = false;
        for (int i = 0; i < dk2::g_MLDPLAY_SESSIONDESC_arr_count; ++i) {
            if (!front->isSessionCompatible[i]) continue;
            hasAnySession = true;
            break;
        }
        if (!hasAnySession) return;  // nothing connect to

        g_auto_network_connect_applied = true;
        if (g_service == SV_TCPIP) {
            dk2::CButton_handleLeftClick_changeMenu(0x00000020, 0x00000054, front);
        } else if (g_service == SV_IPX) {
            dk2::CButton_handleLeftClick_changeMenu(0x00000020, 0x00000021, front);
        } else {
            // patch::log::dbg("(auto network) service \"%s\" is unsupported\n", serviceShort.c_str());
            return;
        }
        if (front->f30C1E != 0) {
            // auto connection success
        }
    }

    void auto_network_main(dk2::CFrontEndComponent *front, std::vector<std::string> &tokens) {
        std::string serviceShort = tokens[0];

        if (serviceShort == "tcpip") {
            g_service = SV_TCPIP;
        } else if (serviceShort == "ipx") {
            g_service = SV_IPX;
        } else {
            patch::log::dbg("(auto network) unknown service \"%s\"\n", serviceShort.c_str());
            return;
        }

        // find service by name
        int serviceIdx = -1;
        for (int i = 0; i < 5; ++i) {
            wchar_t *line = (wchar_t *) dk2::TableStr_selectLine(i, (uint16_t *) dk2::g_network_string_list);
            if (!line) break;
            if (g_service == SV_TCPIP && wcscmp(L"WinSock TCP/IP Internet Connection", line) == 0) {
                serviceIdx = i;
            } else if (g_service == SV_IPX && wcscmp(L"IPX Connection For DirectPlay", line) == 0) {
                serviceIdx = i;
            }
        }
        if (serviceIdx == -1) {
            patch::log::dbg("(auto network) service \"%s\" is not found\n", serviceShort.c_str());
            return;
        }
        dk2::g_listItemNum = serviceIdx;
        dk2::CButton_handleLeftClick_changeMenu(0, 13, front);
        std::string role = tokens.size() > 1 ? tokens[1] : "";
        if (role.empty() || role == "mp") return;
        if (role == "cli") {
            // auto connect to first server
            tryAutoconnect(front);
            patch::scheduler::schedule([front] {
                tryAutoconnect(front);
            }, 5 * 1000);
        } else if (role == "srv") {
            // auto create server with map
            if (g_service == SV_TCPIP) {
                dk2::CButton_handleLeftClick_changeMenu(0x00000020, 0x00000053, front);
            } else if (g_service == SV_IPX) {
                dk2::CButton_handleLeftClick_changeMenu(0x00000020, 0x00000020, front);
            } else {
                patch::log::dbg("(auto network) service \"%s\" is unsupported\n", serviceShort.c_str());
                return;
            }
            std::string levelName = tokens.size() > 2 ? tokens[2] : "";
            std::wstring wLevelName(levelName.begin(), levelName.end());

            bool mapFound = false;
            for (int i = 0; i < front->mapsCount; ++i) {
                auto &map = front->mapInfoArr[i];
                if (map.name != wLevelName) continue;
                front->lobbySelectedMapIdx = i;
                front->lobbyMapWasChanged(i);
                front->loadMapThumbnail(front->getMapName());
                mapFound = true;
                break;
            }

            if (!mapFound) {
                patch::log::dbg("(auto network) map \"%s\" is not found. using default behaviour\n", levelName.c_str());
            }
        } else {
            patch::log::dbg("(auto network) unknown mode \"%s\"\n", role.c_str());
        }
    }

}


flame_config::define_flame_option<std::string> o_auto_network(
    "flame:auto-network",
    "Start game with selected gui\n"
    "format: <service>[:<srv|cli>[:<map>]]\n"
    "\"mp\" - goto Multiplayer\n"
    "\"tcpip\" - goto 'WinSock TCP/IP Internet Connection'\n"
    "\"ipx\" - goto 'IPX Connection For DirectPlay'\n"
    "",
    ""
);


bool patch::auto_network::main(dk2::CFrontEndComponent *front) {
    if (g_auto_network_applied) return false;
    g_auto_network_applied = true;

    std::string autoNetwork = *o_auto_network;
    if (autoNetwork.empty()) return false;

    changeGui(1, MWID_Multiplayer, front);
    CButton_handleLeftClick_changeMenu(0, 8, front);  // collect network services

    std::vector<std::string> tokens = split(autoNetwork, ":");
    auto_network_main(front, tokens);
    return true;
}

void patch::auto_network::onSessionsUpdated(dk2::CFrontEndComponent *front) {
    tryAutoconnect(front);
}
