set(TARGET dkii_flame)

add_executable(${TARGET}
        main.cpp
        dkii_exe_functions.cpp
        dk2/MyResources.cpp
        dk2/MyGame.cpp
        dk2/MyDxMouse.cpp
        dk2/MyDxKeyboard.cpp
        dk2/CFrontEndComponent.cpp
        dk2/CGameComponent.cpp
        dk2/PlayerCfg.cpp
        dk2/RegKey.cpp
        dk2/MyComputerPlayer.cpp
        dk2/entities/entities_type.cpp
        dk2/entities/CCreature.cpp
        dk2/entities/CPlayer.cpp

        patches/replace_mouse_dinput_to_user32.cpp
        patches/use_wheel_to_zoom.cpp
        patches/micro_patches.cpp
        patches/game_version_patch.cpp

        ${DKII_RESOURCES_FILE}
        )
target_include_directories(${TARGET} PRIVATE ${CMAKE_CURRENT_LIST_DIR})
target_compile_definitions(${TARGET} PRIVATE
        DIRECTINPUT_VERSION=0x0500
        DIRECT3D_VERSION=0x0600
        )
target_link_libraries(${TARGET} PRIVATE
        dkii_delinked dkii_exe_api
#        gog_patch_dll

        # dk2 specific libs
        qmixer_genlib  # generated in qmixer_dll/genlib
        weanetr_genlib  # generated in weanetr_dll/genlib

        # the others libs dk2 depends on
        winmm
        dinput_genlib  # generated in dinput_dll/genlib
        ddraw  # patch - dont link against gog's PATCH.dll because patch addresses are change after recompilation
        # also i fully decompiled gog's PATCH.dll and bundled in project

        imm32
        # wsock32 is old link target
        ws2_32 # should be better
        dsound
        Version
        )

target_compile_options(${TARGET} PRIVATE
        /Gy  # Enable Function-Level Linking
        /Gw  # Optimize Global Data
        /GS-
        /Gz  # use __stdcall by default
        /wd4624  # Suppress warning destructor was implicitly defined as deleted
        )
target_link_options(${TARGET} PRIVATE /OPT:NOREF)
target_link_options(${TARGET} PRIVATE /MAP)  # generate msvc mapping file for exe
set_property(TARGET ${TARGET} PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME
        "DKII-Flame${OUTPUT_SUFFIX}"
)


