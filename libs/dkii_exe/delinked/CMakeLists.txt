
set(TARGET dkii_delinked)

set(DELINKED_OBJS
        # dk2
        text.obj
        data.obj
        data_u.obj  # uninitialized part of .data section
        rdata.obj
        # rsrc.obj  # cut out resources

        # another bundled lib
        cseg.obj
        dseg.obj

        # other bundled libs
        grpoly_d.obj
        idct_dat.obj
        lbmpeg_d.obj
        tqia_dat.obj
        uva_data.obj

        # cut out imports chunks into separate obj
        # that's how we make them missing and they become real imports
        # imports.obj

        # cut out chunks we want to rewrite into separate obj
        # decompiled.obj
        )

set(ABS_DELINKED_OBJS ${DELINKED_OBJS})
list(TRANSFORM ABS_DELINKED_OBJS PREPEND "${CMAKE_CURRENT_LIST_DIR}/")
add_custom_command(
        OUTPUT ${ABS_DELINKED_OBJS}
        COMMAND $<TARGET_FILE:delinker>
        -dkii_exe ${CMAKE_HOME_DIRECTORY}/libs/dkii_exe/DKII.EXE
        -sgmap_file ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.sgmap
        -references_file ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.refmap
        -args_sizes ${CMAKE_HOME_DIRECTORY}/mapping/stdcall_args_sizes.map
        -replace_globals ${CMAKE_HOME_DIRECTORY}/src/replace_globals.map
        -delinked ${CMAKE_CURRENT_LIST_DIR}
        DEPENDS delinker
        ${CMAKE_HOME_DIRECTORY}/libs/dkii_exe/DKII.EXE
        ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.sgmap
        ${CMAKE_HOME_DIRECTORY}/mapping/DKII_EXE_v170.refmap
        ${CMAKE_HOME_DIRECTORY}/mapping/stdcall_args_sizes.map
        ${CMAKE_HOME_DIRECTORY}/src/replace_globals.map
        COMMENT "delink DKII.EXE"
)

add_library(${TARGET} STATIC
        stub.cpp  # just to tell cmake library language
        ${DELINKED_OBJS}
        )
