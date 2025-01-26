set(TARGET flame)

add_executable(${TARGET}
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
        dk2/CNetworkCommunication.cpp

        dk2/button/button_types.cpp
        dk2/button/CTextInput.cpp
        dk2/button/button_functions.cpp

        dk2/entities/entities_type.cpp
        dk2/entities/CCreature.cpp
        dk2/entities/CPlayer.cpp

        dk2/engine/draw_functions.cpp
        dk2/engine/window_proc_functions.cpp
        dk2/engine/ddraw_functions.cpp

        tools/bug_hunter.cpp
        tools/StackLimits.cpp
        tools/LoadedModules.cpp
        tools/win32_gui_layout.cpp
        tools/ExceptionWindow.cpp
        tools/command_line.cpp

        patches/replace_mouse_dinput_to_user32.cpp
        patches/use_wheel_to_zoom.cpp
        patches/micro_patches.cpp
        patches/game_version_patch.cpp
        patches/logging.cpp
        patches/inspect_tools.cpp
        patches/original_compatible.cpp

        gog_patch_dll/gog_patch_dll.cpp
        gog_patch_dll/gog_cfg.cpp
        gog_patch_dll/gog_globals.cpp
        gog_patch_dll/gog_fake.cpp
        gog_patch_dll/gog_exports.cpp
        gog_patch_dll/gog_patch.cpp
        gog_patch_dll/fake/FakeD3D.cpp
        gog_patch_dll/fake/FakeD3D2.cpp
        gog_patch_dll/fake/FakeD3D3.cpp
        gog_patch_dll/fake/FakeDevice3.cpp
        gog_patch_dll/fake/FakeDirectDraw1.cpp
        gog_patch_dll/fake/FakeDirectDraw2.cpp
        gog_patch_dll/fake/FakeDirectDraw4.cpp
        gog_patch_dll/fake/FakeGammaControl.cpp
        gog_patch_dll/fake/FakeSurface.cpp
        gog_patch_dll/fake/FakeSurface4.cpp
        gog_patch_dll/fake/FakeTexture.cpp
        gog_patch_dll/fake/FakeViewport3.cpp
        gog_patch_dll/fake/FakeZBuffer.cpp
        gog_patch_dll/fake/FakeUnknown.cpp

        weanetr_dll/NetworkServiceProvider.cpp
        weanetr_dll/BullfrogNET.cpp
        weanetr_dll/DPlay.cpp
        weanetr_dll/DnsResolver.cpp
        weanetr_dll/MLDPlay.cpp
        weanetr_dll/MySocket.cpp
        weanetr_dll/logging.cpp
        weanetr_dll/weanetr.cpp
        weanetr_dll/globals.cpp
        weanetr_dll/weanetr_memory.cpp

#        ${DKII_RESOURCES_FILE}
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
        )
target_link_options(${TARGET} PRIVATE /OPT:NOREF)
target_link_options(${TARGET} PRIVATE /MAP)  # generate msvc mapping file for exe
target_link_options(${TARGET} PRIVATE /DEF:${CMAKE_HOME_DIRECTORY}/libs/dkii_exe/genlib/dkii_exp.def)
set_property(TARGET ${TARGET} PROPERTY
        MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(OUTPUT_NAME "Flame${OUTPUT_SUFFIX}")
set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME
        "${OUTPUT_NAME}_code"
)
set_target_properties(${TARGET} PROPERTIES TARGET_MAP_FILE "${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_NAME}_code.map")


# === Merge Flame.exe with DKII.EXE ===

set(MERGED_EXE "DKII-${OUTPUT_NAME}.exe")
set(ABS_MERGED_EXE ${MERGED_EXE})
list(TRANSFORM ABS_MERGED_EXE PREPEND "${CMAKE_CURRENT_BINARY_DIR}/")

get_target_property(FLAME_MSVCMAP_FILE flame TARGET_MAP_FILE)
get_target_property(FLAME_PDB_FILE flame TARGET_PDB_FILE)
get_target_property(MERGE_SRCS merge_dkii SOURCES)
get_target_property(SOURCE_DIR merge_dkii SOURCE_DIR)
set(ABS_MERGE_SRCS ${MERGE_SRCS})
list(TRANSFORM ABS_MERGE_SRCS PREPEND "${SOURCE_DIR}/")
add_custom_command(
        OUTPUT ${ABS_MERGED_EXE}
        COMMAND ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_HOME_DIRECTORY}/mapping/ida
        ${Python3_EXECUTABLE} ${CMAKE_HOME_DIRECTORY}/tools/merge_dkii/main.py
        # dkii
        -dkii_exe ${CMAKE_HOME_DIRECTORY}/libs/dkii_exe/DKII.EXE
        -dkii_symmap_file ${CMAKE_HOME_DIRECTORY}/libs/dkii_exe/genlib/dkii.symmap
        -dkii_refmap_file ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.refmap
        -dkii_espmap_file ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.espmap
        # flame
        -flame_exe $<TARGET_FILE:flame>
        -flame_msvcmap_file ${FLAME_MSVCMAP_FILE}
        -flame_pdb_file $<TARGET_PDB_FILE:flame>
        -flame_version "${VER_PRODUCT_NUMBER}.${VER_PRODUCT_VERSION}${VER_FILE_SUFFIX}"
        # out
        -output_exe ${ABS_MERGED_EXE}
        DEPENDS ${ABS_MERGE_SRCS}
        ${CMAKE_HOME_DIRECTORY}/libs/dkii_exe/genlib/dkii.symmap
        ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.refmap
        ${CMAKE_HOME_DIRECTORY}/libs/dkii_exe/DKII.EXE
        flame
        COMMENT "Merge Flame.dll with DKII.EXE"
)

add_custom_target(dkii_flame ALL DEPENDS ${ABS_MERGED_EXE})

install(FILES ${ABS_MERGED_EXE} DESTINATION ".")
install(FILES "${CMAKE_CURRENT_BINARY_DIR}/DKII-${OUTPUT_NAME}.map" DESTINATION ".")

if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/dev")
    include(dev/dev.cmake)
endif ()
