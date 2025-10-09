
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

add_subdirectory(lzma2)

# https://github.com/lvandeve/lodepng
add_library(lodepng STATIC lodepng-20221108/lodepng.cpp)
target_include_directories(lodepng PUBLIC lodepng-20221108)
target_compile_options(lodepng PRIVATE /Gz)  # use __stdcall by default
