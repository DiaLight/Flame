
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

# https://github.com/ocornut/imgui
add_library(imgui STATIC
        ## framework
        imgui-1.92.3/imgui.cpp
        imgui-1.92.3/imgui_demo.cpp
        imgui-1.92.3/imgui_draw.cpp
        imgui-1.92.3/imgui_tables.cpp
        imgui-1.92.3/imgui_widgets.cpp

        ## backend
        imgui-1.92.3/backends/imgui_impl_dx9.cpp
        imgui-1.92.3/backends/imgui_impl_win32.cpp
        imgui-1.92.3/backends/imgui_impl_opengl3.cpp
)
target_link_libraries(imgui PUBLIC d3d9)
target_include_directories(imgui PUBLIC
        imgui-1.92.3 imgui-1.92.3/backends
)
target_compile_options(imgui PRIVATE /Gz)  # use __stdcall by default

# https://www.nuget.org/packages/Microsoft.DXSDK.D3DX
target_link_directories(imgui PUBLIC microsoft.dxsdk.d3dx.9.29.952.8.nupkg/build/native/release/lib/x86)
target_include_directories(imgui PUBLIC microsoft.dxsdk.d3dx.9.29.952.8.nupkg/build/native/include)

# https://github.com/nothings/stb
add_library(stb INTERFACE stb-f1c79c0/stb_image.h)
target_include_directories(stb INTERFACE stb-f1c79c0)
