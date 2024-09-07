
add_subdirectory(msvc_mangler)
add_subdirectory(delinker)
add_subdirectory(genapi)
add_subdirectory(genlib_dkii)
add_subdirectory(merge_dkii)
if(DEV_DK2_DIR)
    add_subdirectory(devhelper)
endif()
