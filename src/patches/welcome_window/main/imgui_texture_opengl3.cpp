//
// Created by DiaLight on 11/17/2025.
//

#include "../welcome_window_imgui.h"
#include "imgui_impl_opengl3_loader.h"
#define STB_IMAGE_IMPLEMENTATION 1
#include "stb_image.h"
#include <gl/GL.h>

// Simple helper function to load an image into a OpenGL texture with common settings
ImTextureID patch::welcome_window::LoadTextureFromBuffer(void* data, size_t size, SIZE& texSize) {
    // Load from file
    int image_width = 0;
    int image_height = 0;
    unsigned char* image_data = stbi_load_from_memory((const unsigned char*)data, (int)size, &image_width, &image_height, NULL, 4);
    if (image_data == NULL)
        return false;

    // Create a OpenGL texture identifier
    GLuint image_texture;
    glGenTextures(1, &image_texture);
    glBindTexture(GL_TEXTURE_2D, image_texture);

    // Setup filtering parameters for display
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

    // Upload pixels into texture
    glPixelStorei(GL_UNPACK_ROW_LENGTH, 0);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, image_width, image_height, 0, GL_RGBA, GL_UNSIGNED_BYTE, image_data);
    stbi_image_free(image_data);

    texSize.cx = image_width;
    texSize.cy = image_height;


    return (ImTextureID)(intptr_t)image_texture;
}
