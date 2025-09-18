set(TARGET flame_loader)

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/flame.fpo
        COMMAND ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_HOME_DIRECTORY}/mapping/ida
        ${Python3_EXECUTABLE} ${CMAKE_HOME_DIRECTORY}/tools/extract_fpo/for_flame.py
        -pdb_file $<TARGET_PDB_FILE:flame>
        -fpo_file ${CMAKE_CURRENT_BINARY_DIR}/flame.fpo
        DEPENDS
        flame
        ${CMAKE_HOME_DIRECTORY}/tools/extract_fpo/for_flame.py
        COMMENT "Extract fpo for Flame.dll"
)

add_custom_command(
        OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/dkii.fpo
        COMMAND ${CMAKE_COMMAND} -E env PYTHONPATH=${CMAKE_HOME_DIRECTORY}/mapping/ida
        ${Python3_EXECUTABLE} ${CMAKE_HOME_DIRECTORY}/tools/extract_fpo/for_dkii.py
        -espmap_file ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.espmap
        -fpo_file ${CMAKE_CURRENT_BINARY_DIR}/dkii.fpo
        DEPENDS
        ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.espmap
        ${CMAKE_HOME_DIRECTORY}/tools/extract_fpo/for_dkii.py
        COMMENT "Extract fpo for DKII-DX.exe"
)

set(FLAME_RESOURCES_BIN ${CMAKE_CURRENT_BINARY_DIR}/resources.bin)
add_custom_command(
        OUTPUT ${FLAME_RESOURCES_BIN}
        COMMAND $<TARGET_FILE:resource_compressor>
        -refmap_file ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.refmap
        -symmap_file ${CMAKE_HOME_DIRECTORY}/libs/dkii_exe/genlib/dkii.symmap
        -dkii_fpobin_file ${CMAKE_CURRENT_BINARY_DIR}/dkii.fpo
        -flame_fpobin_file ${CMAKE_CURRENT_BINARY_DIR}/flame.fpo
        -version "${VER_PRODUCT_NUMBER}.${VER_PRODUCT_VERSION}${VER_FILE_SUFFIX}"
        -res_file ${FLAME_RESOURCES_BIN}
        DEPENDS
        resource_compressor
        ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.refmap
        ${CMAKE_HOME_DIRECTORY}/libs/dkii_exe/genlib/dkii.symmap
        ${CMAKE_CURRENT_BINARY_DIR}/dkii.fpo
        ${CMAKE_CURRENT_BINARY_DIR}/flame.fpo
        COMMENT "Pack Flame resources"
)

set(RESOURCES_FILE ${CMAKE_CURRENT_BINARY_DIR}/resources.rc)
set(VER_PRODUCT_NAME "Flame loader")
set(VER_DESCRIPTION "Runtime Flame loader and linker v${OUTPUT_VERSION}")
configure_file(
        ${CMAKE_CURRENT_LIST_DIR}/resources.rc.in
        ${RESOURCES_FILE}
        @ONLY
)

add_library(${TARGET} SHARED
        main.cpp
        dependency_injection.cpp
        Symbol.cpp
        logging.cpp
        ${RESOURCES_FILE}
)
set_source_files_properties(${RESOURCES_FILE} OBJECT_DEPENDS ${FLAME_RESOURCES_BIN})
target_link_libraries(${TARGET} PRIVATE Cabinet references)

set(OUTPUT_NAME "PATCH")
target_compile_definitions(${TARGET} PRIVATE BELIKE_DDRAW=1)  # aka PATCH.dll

#set(OUTPUT_NAME "ole32")
#target_compile_definitions(${TARGET} PRIVATE BELIKE_OLE32=1)

#set(OUTPUT_NAME "dinput")
#target_compile_definitions(${TARGET} PRIVATE BELIKE_DINPUT=1)

set_target_properties(${TARGET} PROPERTIES OUTPUT_NAME "${OUTPUT_NAME}")

install(FILES $<TARGET_FILE:${TARGET}> DESTINATION ".")
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    target_link_options(${TARGET} PRIVATE /PDBALTPATH:flame/${OUTPUT_NAME}.pdb)
    install(FILES $<TARGET_PDB_FILE:${TARGET}> DESTINATION "flame")
endif()
