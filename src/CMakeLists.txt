set(TARGET flame)

set(RESOURCES_FILE ${CMAKE_CURRENT_BINARY_DIR}/resources.rc)
set(VER_PRODUCT_NAME "DKII Flame")
set(VER_DESCRIPTION "DKII Flame unofficial patches v${OUTPUT_VERSION}")
configure_file(
        ${CMAKE_CURRENT_LIST_DIR}/resources.rc.in
        ${RESOURCES_FILE}
        @ONLY
)

function(collect_sources OUT PREFIX)
    include(${PREFIX}/sources.cmake)
    list(TRANSFORM SOURCES PREPEND ${PREFIX}/)
    set(${OUT} ${SOURCES} PARENT_SCOPE)
endfunction()

collect_sources(MAIN_LAYOUT_SOURCES dk2/gui/main)
collect_sources(GAME_LAYOUT_SOURCES dk2/gui/game)
collect_sources(GOG_PATCH_SOURCES gog_patch_dll)
collect_sources(WEANETR_SOURCES weanetr_dll)

add_library(${TARGET} SHARED
        main.cpp
        dkii_exe_functions.cpp
        dk2/MyResources.cpp
        dk2/MyGame.cpp
        dk2/MyDxMouse.cpp
        dk2/MyDxKeyboard.cpp
        dk2/CFrontEndComponent.cpp
        dk2/CGameComponent.cpp
        dk2/CDefaultPlayerInterface.cpp
        dk2/PlayerCfg.cpp
        dk2/RegKey.cpp
        dk2/MyComputerPlayer.cpp
        dk2/CRoom.cpp
        dk2/CBridge.cpp
        dk2/CCamera.cpp
        dk2/CWorld.cpp
        dk2/WeaNetR.cpp
        dk2/dk2_memory.cpp
        dk2/dk2_command_line.cpp
        dk2/CNetworkCommunication.cpp
        dk2/MyComputerPlayer_drop_condition.cpp
        dk2/computer_player_flags.cpp
        dk2/MyCreatureCollection.cpp
        dk2/MyComputerPlayer_drop_condition.cpp
        dk2/MyComputerPlayer_drop_condition.h
        dk2/computer_player_flags.cpp
        dk2/computer_player_flags.h

        dk2/math/int_float.cpp

        dk2/button/button_types.cpp
        dk2/button/CTextInput.cpp
        dk2/button/button_functions.cpp
        dk2/button/CClickButton.cpp

        dk2/entities/entities_type.cpp
        dk2/entities/CCreature.cpp
        dk2/entities/CCreatureExtended.cpp
        dk2/entities/CPlayer.cpp

        dk2/engine/draw_functions.cpp
        dk2/engine/window_proc_functions.cpp
        dk2/engine/ddraw_functions.cpp

        dk2/surface/surface_functions.cpp

        dk2/network/protocol.cpp

        ${MAIN_LAYOUT_SOURCES}
        ${GAME_LAYOUT_SOURCES}

        dk2/gui/main_gui.cpp
        dk2/gui/CDefaultPlayerInterface_game_gui.cpp
        dk2/gui/CGuiManager.cpp
        dk2/gui/visual_debug.cpp
        dk2/gui/button_render.cpp

        tools/StackLimits.cpp
        tools/LoadedModules.cpp
        tools/win32_gui_layout.cpp
        tools/ExceptionWindow.cpp
        tools/command_line.cpp
        tools/console.cpp
        tools/last_error.cpp
        tools/flame_config.cpp

        tools/bug_hunter.cpp
        tools/bug_hunter/StackWalker.cpp
        tools/bug_hunter/StackWalkerState.cpp
        tools/bug_hunter/StackWalkerIter.cpp
        tools/bug_hunter/WalkerError.cpp
        tools/bug_hunter/StackFrame.cpp

        patches/flame_main.cpp
        patches/replace_mouse_dinput_to_user32.cpp
        patches/use_wheel_to_zoom.cpp
        patches/micro_patches.cpp
        patches/game_version_patch.cpp
        patches/logging.cpp
        patches/inspect_tools.cpp
        patches/original_compatible.cpp
        patches/protocol_dump.cpp
        patches/screen_resolution.cpp
        patches/registry_to_config.cpp
        patches/limit_tps.cpp
        patches/auto_network.cpp
        patches/scheduler.cpp

        patches/gui/main/main_layout.cpp
        patches/gui/main/single_player/btn_custom_campaign.cpp
        patches/gui/main/single_player/win_custom_campaign.cpp

        patches/gui/game/game_layout.cpp
        patches/gui/game/esc_options/btn_autosave.cpp

        ${GOG_PATCH_SOURCES}
        ${WEANETR_SOURCES}

        ${RESOURCES_FILE}
        )
target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_LIST_DIR} gog_patch_dll)
target_compile_definitions(${TARGET} PRIVATE
        DIRECTINPUT_VERSION=0x0500
        DIRECT3D_VERSION=0x0600
        )
target_link_libraries(${TARGET} PRIVATE
        dkii_genlib dkii_exe_api
#        gog_patch_dll

        # dk2 specific libs
        qmixer_genlib  # generated in qmixer_dll/genlib
        weanetr_genlib  # generated in weanetr_dll/genlib
        dplay_headers

        # the others libs dk2 depends on
        winmm
        dinput_genlib  # generated in dinput_dll/genlib
        ddraw  # patch - dont link against gog's PATCH.dll because patch addresses are change after recompilation
        dxguid

        # 3rdparty
        cimg  # visual debug
        toml  # flame config

        imm32
        # wsock32 is old link target
        ws2_32 # should be better
        dsound
        Version
        Dbghelp
        )

target_compile_options(${TARGET} PRIVATE
        /Gy  # Enable Function-Level Linking
        /Gw  # Optimize Global Data
#        /GL  # Whole program optimization
        /GS-  # Buffer Security Check
        /Gz  # use __stdcall by default
        /wd4624  # Suppress warning destructor was implicitly defined as deleted
        /Zc:threadSafeInit-
#        /Oy  # Frame-Pointer Omission
        /Zi  # Produces a separate PDB file that contains all the symbolic debugging information
)
target_link_options(${TARGET} PRIVATE /debug)  # generate pdb to extract FPO and mapping with release builds
target_link_options(${TARGET} PRIVATE /OPT:NOREF)
target_link_options(${TARGET} PRIVATE /DEF:${CMAKE_HOME_DIRECTORY}/libs/dkii_exe/genlib/dkii_exp.def)
set(OUTPUT_NAME "Flame")
set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME "${OUTPUT_NAME}")


install(FILES $<TARGET_FILE:${TARGET}> DESTINATION "flame")
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_link_options(${TARGET} PRIVATE /PDBALTPATH:${OUTPUT_NAME}.pdb)
    install(FILES $<TARGET_PDB_FILE:${TARGET}> DESTINATION "flame")
endif()

if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/../dev")
    include(../dev/dev.cmake)
endif ()
