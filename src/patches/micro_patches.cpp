//
// Created by DiaLight on 20.07.2024.
//

#include <WinSock2.h>
#include <WS2tcpip.h>
#include "micro_patches.h"

#include <tools/flame_config.h>

#include "dk2/utils/Pos2i.h"
#include "dk2/utils/AABB.h"
#include "dk2/MyMouseUpdater.h"
#include "dk2/MyDxInputState.h"
#include "dk2_globals.h"
#include "dk2_functions.h"
#include "logging.h"
#include "tools/command_line.h"
#include "inspect_tools.h"


bool patch::modern_windows_support::enabled = true;
bool patch::use_cwd_as_dk2_home_dir::enabled = true;
bool patch::notify_another_instance_is_running::enabled = true;
bool patch::control_windowed_mode::enabled = false;
bool patch::force_32bit_everything::enabled = true;
bool patch::disable_bonus_damage::enabled = false;
bool patch::backstab_fix::enabled = true;
bool patch::workshop_manufacture_build_time_fix::enabled = true;
bool patch::response_to_threat_fix::enabled = true;
bool patch::blocking_response_to_threat_fix::enabled = true;
bool patch::use_wasd_by_default_patch::enabled = true;
bool patch::print_game_start_errors::enabled = true;
bool patch::creatures_setup_lair_fix::enabled = true;
bool patch::wooden_bridge_burn_fix::enabled = true;
bool patch::max_host_port_number_fix::enabled = true;
bool patch::increase_zoom_level::enabled = true;
bool patch::fix_chat_buffer_invalid_memory_access::enabled = true;
bool patch::hero_party_spawn_limit_fix::enabled = true;
bool patch::drop_thing_from_hand_fix::enabled = true;  // incompatible with 1.7
bool patch::sleeping_possession_fix::enabled = true;
bool patch::while_without_syscall_fix::enabled = true;
bool patch::display_incompatible_reason::enabled = true;
bool patch::big_resolution_fix::enabled = true;


void draw_missing_argb32(dk2::MySurface &surf, int scale) {
    uint8_t *line = (uint8_t *) surf.lpSurface;
    for (int y = 0; y < surf.dwHeight; ++y) {
        uint8_t *pos = line;
        for (int x = 0; x < surf.dwWidth; ++x) {
            uint32_t *pix = (uint32_t *) pos;
            if ((((x/ scale) ^ (y / scale)) & 1) == 0) {
                *pix = 0xFF202020;
            } else {
                *pix = 0xFF800080;
            }
            pos += (surf.desc.dwRGBBitCount + 7) / 8;
        }
        line += surf.lPitch;
    }
}
bool patch::null_surf_fix::enabled = true;
dk2::MySurface patch::null_surf_fix::emptySurf;
void patch::null_surf_fix::init() {
    emptySurf.constructor_empty();
    dk2::Size2i size = {64, 64};
    dk2::MySurfDesc desc = {
        0x00FF0000, 0x0000FF00, 0x000000FF, 0xFF000000,
        32, 0
    };
    emptySurf.constructor(&size, &desc, NULL, 0);
    int status;
    emptySurf.allocSurfaceIfNot(&status);
    draw_missing_argb32(emptySurf, 8);
}


flame_config::define_flame_option<int> o_experimentalRoomsLimit(
    "flame:experimental:rooms-limit",
    "Extending rooms limit. DK2 1.7 value is 96. max value: 255\n",
    255
);
uint8_t patch::override_max_room_count::getLimit() {
    return *o_experimentalRoomsLimit;
}

void patch::use_wasd_by_default_patch::useAlternativeName(LPCSTR &lpValueName) {
    if(!use_wasd_by_default_patch::enabled) return;
    if(lpValueName && strncmp(lpValueName, "Key Table", 12) == 0) {
        lpValueName = "Key Table Flame";
    }
}

void patch::fix_keyboard_state_on_alt_tab::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
        case WM_ACTIVATEAPP:
            if (wParam) {  // activated
                // clear buttons state
                dk2::MyDxInputState *inputState = dk2::MyInputManagerCb_instance.pdxInputState;
                if(inputState != nullptr) {
                    memset(inputState->keyboardState, 0, 256);
                }
            }
            break;
    }
}

void patch::bring_to_foreground::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
        case WM_CREATE: {
            SetForegroundWindow(hWnd);
            break;
        }
    }
}

namespace dk2 {
    enum GameActionKind : DWORD {
        GA_ExitToWindows = 0x7D
    };
}

bool patch::fix_close_window::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
        case WM_CLOSE: {
            dk2::CDefaultPlayerInterface *playetIf = &dk2::CDefaultPlayerInterface_instance;
            if (playetIf->profiler != nullptr) {  // game is running
                dk2::GameAction action;
                ZeroMemory(&action, sizeof(action));
                action.actionKind = dk2::GA_ExitToWindows;
                action.playerTagId = playetIf->playerTagId;
                playetIf->pushAction(&action);
                return false;
            } else {
                dk2::setAppExitStatus(true);
            }
            break;
        }
    }
    return true;
}

namespace {
    bool appIsActive = false;
}
bool patch::hide_mouse_cursor_in_window::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
        case WM_SETCURSOR: {
            if(appIsActive) {
                if (LOWORD(lParam) == HTCLIENT) {
                    SetCursor(NULL);
                    return true;
                }
            }
            break;
        }
        case WM_ACTIVATEAPP:
            if (wParam) {  // activated
                SetCursor(NULL);
                appIsActive = true;
            } else {  // deactivated
                appIsActive = false;
            }
            break;
    }
    return false;
}

namespace {
    POINT window_pos = {50, 50};
    POINT window_size = {0, 0};
    bool ignore_size = true;
}
void patch::remember_window_location_and_size::setInitialSize(int x, int y) {
    window_size = {x, y};
}

bool patch::remember_window_location_and_size::window_proc(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam) {
    switch(Msg) {
        case WM_DESTROY: {
            ignore_size = true;
            break;
        }
        case WM_MOVE: {
            RECT winRect;
            GetWindowRect(hWnd, &winRect);
            window_pos = {winRect.left, winRect.top};

            break;
        }
        case WM_SIZE: {
            if(!ignore_size) {
                RECT winRect;
                GetWindowRect(hWnd, &winRect);
                window_size = {winRect.right - winRect.left, winRect.bottom - winRect.top};
            }
            break;
        }
    }
    return false;
}
void patch::remember_window_location_and_size::patchWinLoc(int &xPos, int &yPos) {
    xPos = window_pos.x;
    yPos = window_pos.y;
}
void patch::remember_window_location_and_size::resizeWindow(HWND hWnd) {
    if(window_size.x != 0 && window_size.y != 0) {
        SetWindowPos(hWnd, NULL, 0, 0, window_size.x, window_size.y, SWP_NOMOVE | SWP_NOZORDER);
    }
    ignore_size = false;
}

bool patch::skippable_title_screen::enabled = true;
uint32_t patch::skippable_title_screen::waiting_time = 600;  // in milliseconds. by default 10 seconds
bool patch::skippable_title_screen::skipKeyPressed() {
    if(GetAsyncKeyState(VK_SPACE) & 0x8000) return true;
    if(GetAsyncKeyState(VK_ESCAPE) & 0x8000) return true;
    if(GetAsyncKeyState(VK_LBUTTON) & 0x8000) return true;
    if(GetAsyncKeyState(VK_RETURN) & 0x8000) return true;
    SleepEx(50, TRUE);
    return false;
}


flame_config::define_flame_option<std::string> o_myip(
    "flame:myip",
    "force set local ip address in network sessions",
    ""
);
bool patch::multi_interface_fix::enabled = true;
std::vector<ULONG> patch::multi_interface_fix::localAddresses;
ULONG patch::multi_interface_fix::userProvidedIpv4 = 0;
void patch::multi_interface_fix::init() {
    std::string ipv4Str = *o_myip;
    if (ipv4Str.empty()) return;
    // if user specified address by flags, use it
    struct sockaddr_in sa;
    if(::inet_pton(AF_INET, ipv4Str.c_str(), &(sa.sin_addr)) == 1) {
        printf("[multi_interface_fix] force use provided by flags ipv4 %s\n", ipv4Str.c_str());
        userProvidedIpv4 = sa.sin_addr.S_un.S_addr;
    } else {
        MessageBoxA(NULL, "you provided invalid flame:myip option", "Flame:multi_interface_fix", MB_OK);
        exit(1);
    }
}
void patch::multi_interface_fix::replaceLocalIp(struct hostent *hostent, ULONG &ipv4) {
    if(!patch::multi_interface_fix::enabled) return;
    localAddresses.clear();
    if(userProvidedIpv4 != 0) {
        if(patch::inspect_tools::enable) {
            printf("[multi_interface_fix]  replace local %s", ::inet_ntoa(*(struct in_addr *) &ipv4));
            printf(" -> %s\n", ::inet_ntoa(*(struct in_addr *) &userProvidedIpv4));
        }
        ipv4 = userProvidedIpv4;
        return;
    }
    if(patch::inspect_tools::enable)  // todo: verbose logging flags
        printf("[multi_interface_fix] remember resolved ips from local hostname %s\n", hostent->h_name);
    for(int i = 0; ; ++i) {
        in_addr *addr = (in_addr *) hostent->h_addr_list[i];
        if(addr == NULL) break;
        if(patch::inspect_tools::enable)
            printf("[multi_interface_fix]  - %s\n", ::inet_ntoa(*addr));
        localAddresses.push_back(addr->S_un.S_addr);
    }
}

void patch::multi_interface_fix::replaceConnectAddress(_Inout_ DWORD &ipv4, net::MySocket &to) {
    if(!patch::multi_interface_fix::enabled) return;
    ULONG wouldBeUsed = ipv4;
    std::string wouldBeUsedStr = ::inet_ntoa(*(struct in_addr *) &wouldBeUsed);
    std::string toStr = ::inet_ntoa(*(struct in_addr *) &to.ipv4);

    // dirty algorithm. but it works in local networks
    ULONG mostSimilar = 0;
    int mostSimilar_bitsMatched = 0;
    for (ULONG local_ipv4 : localAddresses) {
        int i = 0;
        for (; i < sizeof(ULONG) * 8; ++i) {
            if(((to.ipv4 >> i) & 1) != ((local_ipv4 >> i) & 1)) break;
        }
        if(i > mostSimilar_bitsMatched) {
            mostSimilar_bitsMatched = i;
            mostSimilar = local_ipv4;
        }
    }

    if(mostSimilar != 0 && mostSimilar != wouldBeUsed) {
        static_assert(sizeof(struct in_addr) == sizeof(ULONG));
        std::string mostSimilarStr = ::inet_ntoa(*(struct in_addr *) &mostSimilar);
        patch::log::dbg("[multi_interface_fix] replace local ip %s -> %s as %d bits matched with remote %s",
                wouldBeUsedStr.c_str(),
                mostSimilarStr.c_str(),
                mostSimilar_bitsMatched,
                toStr.c_str()
        );
        ipv4 = mostSimilar;
    }
}
