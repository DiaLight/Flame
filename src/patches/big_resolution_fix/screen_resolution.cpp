//
// Created by DiaLight on 4/6/2025.
//
#include "screen_resolution.h"

#include <dk2_globals.h>
#include <iostream>
#include <ostream>
#include <tools/command_line.h>
#include <tools/flame_config.h>


extern bool patch::screen_resolution::enabled = true;

flame_config::define_flame_option<std::string> o_menuRes(
    "flame:menu-res", flame_config::OG_Config,
    "Force set Menu resolution\n"
    "dk2 supported values:\n"
    "- 640x480\n"
    // 1024x768
    // 1280x1024
    // 1600x1200
    // 1440x900
    // 1920x1440
    "",
    ""
);

flame_config::define_flame_option<std::string> o_gameRes(
    "flame:game-res", flame_config::OG_Config,
    "Force set Game resolution. overrides registry:configuration:video:Screen_[Width,Height] controlled by dk2\n"
    "dk2 supported values:\n"
    "- 400x300\n"
    "- 512x384\n"
    "- 640x480\n"
    "- 800x600\n"
    "- 1024x768\n"
    "- 1280x1024\n"
    "- 1600x1200\n"
    // 1366x768  // +
    //
    // 1920x1440
    // 2560x1440
    // 2560x1600
    // 3840x2160
    "",
    ""
);

namespace {
    uint32_t menuWidth = 0;
    uint32_t menuHeight = 0;
    uint32_t gameWidth = 0;
    uint32_t gameHeight = 0;
}

bool tryGetUInt(const std::string &s, uint32_t &value) {
    try {
        value = std::stoul(s, nullptr, 10);
        return true;
    } catch(const std::invalid_argument &e) {
        std::cout << "[error] " << s << std::endl;
        return false;
    }
}
bool tryParseRes(const std::string &s, uint32_t &width, uint32_t &height) {
    auto it = s.find('x');
    if (it == std::string::npos) {
        std::cout << "[error] 'x' is not found" << std::endl;
        return false;
    }
    if (!tryGetUInt(s.substr(0, it), width)) return false;
    if (!tryGetUInt(s.substr(it + 1), height)) return false;
    return true;
}
void parseRes(const std::string &s, uint32_t &width, uint32_t &height) {
    if (!tryParseRes(s, width, height)) {
        std::cout << "[error] invalid res value \"" << s << "\"" << std::endl;
        exit(-1);
    }
}

void patch::screen_resolution::init() {
    if (!enabled) return;
    auto menuRes = *o_menuRes;
    if (!menuRes.empty()) {
        parseRes(menuRes, menuWidth, menuHeight);
    }

    auto gameRes = *o_gameRes;
    if (!gameRes.empty()) {
        parseRes(gameRes, gameWidth, gameHeight);
    }
}

void patch::screen_resolution::patchMenuWindowResolution(uint32_t &width, uint32_t &height) {
    if (!enabled) return;
    if (menuWidth && menuHeight) {
        width = menuWidth;
        height = menuHeight;
    }
}
void patch::screen_resolution::patchGameWindowResolution() {
    if (!enabled) return;
    if (gameWidth && gameHeight) {
        dk2::MyVideoSettings &settings = dk2::MyResources_instance.video_settings;
        settings.display_width = gameWidth;
        settings.display_height = gameHeight;
    }
}

