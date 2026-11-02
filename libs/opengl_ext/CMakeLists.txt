
add_library(glext INTERFACE GL/glext.h)
target_include_directories(glext INTERFACE ${CMAKE_CURRENT_LIST_DIR})
