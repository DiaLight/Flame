find_program(LIB_PROGRAM lib)
find_program(DUMPBIN_PROGRAM dumpbin)

set(GENLIB_LIB dkii.lib)

set(ABS_GENLIB_LIB ${GENLIB_LIB})
list(TRANSFORM ABS_GENLIB_LIB PREPEND "${CMAKE_CURRENT_LIST_DIR}/")

#get_target_property(GENAPI_SRCS genlib_dkii SOURCES)
#get_target_property(SOURCE_DIR genlib_dkii SOURCE_DIR)
#set(ABS_GENAPI_SRCS ${GENAPI_SRCS})
#list(TRANSFORM ABS_GENAPI_SRCS PREPEND "${SOURCE_DIR}/")
add_custom_command(
        OUTPUT ${ABS_GENLIB_LIB}
        ${CMAKE_CURRENT_LIST_DIR}/dkii.symmap
        ${CMAKE_CURRENT_LIST_DIR}/dkii_stub.asm
        COMMAND $<TARGET_FILE:genlib_dkii>
        -sgmap_file ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.sgmap
        -def_file ${CMAKE_CURRENT_LIST_DIR}/dkii.def
        -replace_globals ${CMAKE_HOME_DIRECTORY}/src/replace_globals.map
        -exp_file ${CMAKE_CURRENT_LIST_DIR}/dkii_exp.def
        -map_file ${CMAKE_CURRENT_LIST_DIR}/dkii.symmap
        -asm_stub_file ${CMAKE_CURRENT_LIST_DIR}/dkii_stub.asm
        COMMAND cmd /C ${CMAKE_HOME_DIRECTORY}/tools/genlib/gen_lib.bat
        ${LIB_PROGRAM} ${CMAKE_HOME_DIRECTORY}/libs/dkii_exe/genlib/dkii.def ${ABS_GENLIB_LIB}
        DEPENDS
        ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.sgmap
        ${CMAKE_HOME_DIRECTORY}/src/replace_globals.map
        COMMENT "genlib DKII.EXE"
)


set(TARGET dkii_genlib)
add_library(${TARGET} INTERFACE
        ${GENLIB_LIB}  # make target depend on lib file building
        )
target_link_libraries(${TARGET} INTERFACE ${GENLIB_LIB})  # make target share lib dependency with others
target_link_directories(${TARGET} INTERFACE ${CMAKE_CURRENT_LIST_DIR})  # make other targets able to find lib file


set(TARGET dkii_dll_stub)

enable_language(C ASM_MASM)
STRING (REGEX REPLACE "/RTC1" "" CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}")

set(RESOURCES_FILE ${CMAKE_CURRENT_BINARY_DIR}/resources.rc)
set(VER_PRODUCT_NAME "DKII stub")
set(VER_DESCRIPTION "DKII stub for Flame v${OUTPUT_VERSION}")
configure_file(
        ${CMAKE_CURRENT_LIST_DIR}/resources.rc.in
        ${RESOURCES_FILE}
        @ONLY
)

add_library(${TARGET} SHARED
        dkii_stub.cpp
        dkii_stub.asm
        # bug: MSVC compiler 19.44.35217.0 sometimes cant handle resource file in this target debug build
        # log: LINK : fatal error LNK1000: unknown error at 00BD059D; consult documentation for technical support options
        #${RESOURCES_FILE}
)
set_target_properties(${TARGET} PROPERTIES LINK_FLAGS "/NODEFAULTLIB")

set(OUTPUT_NAME "DKII")
set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME "${OUTPUT_NAME}")

install(FILES $<TARGET_FILE:${TARGET}> DESTINATION "flame")
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_link_options(${TARGET} PRIVATE /PDBALTPATH:${OUTPUT_NAME}.pdb)
    install(FILES $<TARGET_PDB_FILE:${TARGET}> DESTINATION "flame")
    target_link_options(${TARGET} PRIVATE /ILK:${CMAKE_CURRENT_BINARY_DIR}/${OUTPUT_NAME}.ilk)  # dont put ilk to bin dir
endif()
set_target_properties(${TARGET} PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin/flame")
