
add_subdirectory(dkii_exe)
#add_subdirectory(gog_patch_dll)  # not ready yet
add_subdirectory(qmixer_dll)
add_subdirectory(weanetr_dll)
add_subdirectory(dinput_dll)
add_subdirectory(dplay_dll)

# used for debug purposes
add_library(cimg INTERFACE CImg-3.5.3/CImg.h)
target_include_directories(cimg INTERFACE CImg-3.5.3)
