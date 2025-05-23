//
// Created by DiaLight on 19.01.2025.
//

#include "original_compatible.h"

#include <tools/flame_config.h>

#include "dk2_globals.h"
#include "tools/command_line.h"
#include "micro_patches.h"


bool patch::original_compatible::enable = false;

flame_config::define_flame_option<bool> o_original_compatible(
    "flame:original-compatible",
    "Flame will try to be compatible with DKII-DX.EXE v1.7.0\n"
    "All patches that breaks network compatibility will be disabled\n"
    "[drop_thing_from_hand_fix, override_max_room_count, backstab_fix, workshop_manufacture_build_time_fix, wooden_bridge_burn_fix, sleeping_possession_fix] will be disabled\n",
    false
);

extern flame_config::define_flame_option<int> o_experimentalRoomsLimit;
void patch::original_compatible::init() {
    original_compatible::enable = o_original_compatible.get();
    if(!original_compatible::enable) return;
    printf("[original_compatible] Flame will try to be compatible with DKII-DX.EXE v1.7.0\n");

    // minimal required to disable
    drop_thing_from_hand_fix::enabled = false;  // incompatible with 1.7
    o_experimentalRoomsLimit.set_tmp(96);

    // disable fixes that will cause desynchronization
//    add_win10_support::enabled = true;  // backward compatible
//    use_cwd_as_dk2_home_dir::enabled = true;  // backward compatible
//    notify_another_instance_is_running::enabled = true;  // backward compatible
//    control_windowed_mode::enabled = false;  // backward compatible
//    force_32bit_everything::enabled = true;  // backward compatible
//    disable_bonus_damage::enabled = false;  // enabling will cause desync
    backstab_fix::enabled = false;
    workshop_manufacture_build_time_fix::enabled = false;
//    response_to_threat_fix::enabled = true;  // probably only server side
//    use_wasd_by_default_patch::enabled = true;  // backward compatible
//    print_game_start_errors::enabled = true;  // backward compatible
//    creatures_setup_lair_fix::enabled = true;  // probably only server side
    wooden_bridge_burn_fix::enabled = false;
//    max_host_port_number_fix::enabled = true;  // backward compatible
//    increase_zoom_level::enabled = true;  // backward compatible
//    fix_chat_buffer_invalid_memory_access::enabled = true;  // backward compatible
//    hero_party_spawn_limit_fix::enabled = true;  // probably only server side
    sleeping_possession_fix::enabled = false;
}

void patch::original_compatible::patch_hashsum() {
    if(!original_compatible::enable) return;
    dk2::g_fileHashsum = 0xFF542FAC;  // DKII-DX.exe v1.7
//    dk2::g_fileHashsum = 0xBB187BFA;  // devht
}

