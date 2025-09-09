set(TARGET flame_loader)


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
        ${RESOURCES_FILE}
)
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
