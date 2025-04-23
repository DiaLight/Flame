
add_subdirectory(dkii_exe)
#add_subdirectory(gog_patch_dll)  # not ready yet
add_subdirectory(qmixer_dll)
add_subdirectory(weanetr_dll)
add_subdirectory(dinput_dll)
add_subdirectory(dplay_dll)

# 3rd party libs

# https://github.com/GreycLab/CImg
add_library(cimg INTERFACE CImg-3.5.3/CImg.h)
target_include_directories(cimg INTERFACE CImg-3.5.3)

# https://github.com/ToruNiina/toml11
add_library(toml INTERFACE Toml11-4.4.0/toml.hpp)
target_include_directories(toml INTERFACE Toml11-4.4.0)
