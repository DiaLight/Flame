//
// Created by DiaLight on 5/31/2026.
//

#include "opengl_internal.h"
#include "dk2_functions.h"
#include "tools/visual_debug.h"
#include "dk2/utils/Bgra.h"
#include <windows.h>
#include <iostream>
#include <vector>
#include <bitset>


bool OglCtx::_init(HDC hdc) {

    // Set pixel format
    PIXELFORMATDESCRIPTOR pfd = {};
    pfd.nSize = sizeof(PIXELFORMATDESCRIPTOR);
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_DRAW_TO_WINDOW | PFD_SUPPORT_OPENGL | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 32;
    pfd.cDepthBits = 24;
    pfd.iLayerType = PFD_MAIN_PLANE;

    int pfdIndex = ChoosePixelFormat(hdc, &pfd);
    if (!pfdIndex) {
        std::cerr << "Failed to choose pixel format!" << std::endl;
        return false;
    }
    if (!SetPixelFormat(hdc, pfdIndex, &pfd)) {
        std::cerr << "Failed to set pixel format!" << std::endl;
        return false;
    }

    // Create rendering context
    this->hglrc = wglCreateContext(hdc);
    if (!this->hglrc) {
        std::cerr << "Failed to create OpenGL context!" << std::endl;
        return false;
    }
    if (!wglMakeCurrent(hdc, this->hglrc)) {
        std::cerr << "Failed to make OpenGL context current!" << std::endl;
        wglDeleteContext(this->hglrc);
        this->hglrc = nullptr;
        return false;
    }
    return true;
}

bool render_init();
bool OglCtx::init(HWND hWnd) {
    // Initialize OpenGL outside WndProc
    this->hwnd = hWnd;
    this->hdc = GetDC(hWnd);
    if (!this->hdc) {
        std::cerr << "Failed to get device context!" << std::endl;
        return false;
    }

    if (!this->_init(this->hdc)) {
        std::cerr << "Failed to initialize OpenGL!" << std::endl;
        ReleaseDC(hWnd, this->hdc);
        return false;
    }


    // Helper function to load OpenGL function pointers
    auto loadGLFunc = []<typename T>(const char* funcName, T& ref) -> bool {
        ref = reinterpret_cast<T>(wglGetProcAddress(funcName));
        if (!ref) {
            std::cerr << "Failed to load OpenGL function: " << funcName << std::endl;
            return false;
        }
        return true;
    };

    // Load core OpenGL functions
    if (!loadGLFunc("glGetStringi", glGetStringi)) return false;
    if (!loadGLFunc("glGenerateMipmap", glGenerateMipmap)) return false;
    if (!loadGLFunc("glActiveTexture", glActiveTexture)) return false;
    if (!loadGLFunc("glClientActiveTexture", glClientActiveTexture)) return false;

    // Load vertex array and buffer functions (OpenGL 3.0+)
    if (!loadGLFunc("glGenVertexArrays", glGenVertexArrays)) return false;
    if (!loadGLFunc("glBindVertexArray", glBindVertexArray)) return false;
    if (!loadGLFunc("glDeleteVertexArrays", glDeleteVertexArrays)) return false;
    if (!loadGLFunc("glGenBuffers", glGenBuffers)) return false;
    if (!loadGLFunc("glBindBuffer", glBindBuffer)) return false;
    if (!loadGLFunc("glDeleteBuffers", glDeleteBuffers)) return false;
    if (!loadGLFunc("glBufferData", glBufferData)) return false;
    if (!loadGLFunc("glVertexAttribPointer", glVertexAttribPointer)) return false;
    if (!loadGLFunc("glEnableVertexAttribArray", glEnableVertexAttribArray)) return false;
    if (!loadGLFunc("glDisableVertexAttribArray", glDisableVertexAttribArray)) return false;

    // Load shader functions (OpenGL 2.0+)
    if (!loadGLFunc("glCreateShader", glCreateShader)) return false;
    if (!loadGLFunc("glShaderSource", glShaderSource)) return false;
    if (!loadGLFunc("glCompileShader", glCompileShader)) return false;
    if (!loadGLFunc("glCreateProgram", glCreateProgram)) return false;
    if (!loadGLFunc("glLinkProgram", glLinkProgram)) return false;
    if (!loadGLFunc("glAttachShader", glAttachShader)) return false;
    if (!loadGLFunc("glDetachShader", glDetachShader)) return false;
    if (!loadGLFunc("glDeleteShader", glDeleteShader)) return false;
    if (!loadGLFunc("glDeleteProgram", glDeleteProgram)) return false;
    if (!loadGLFunc("glGetShaderiv", glGetShaderiv)) return false;
    if (!loadGLFunc("glGetShaderInfoLog", glGetShaderInfoLog)) return false;
    if (!loadGLFunc("glGetProgramiv", glGetProgramiv)) return false;
    if (!loadGLFunc("glGetProgramInfoLog", glGetProgramInfoLog)) return false;
    if (!loadGLFunc("glGetUniformLocation", glGetUniformLocation)) return false;
    if (!loadGLFunc("glGetAttribLocation", glGetAttribLocation)) return false;
    if (!loadGLFunc("glUseProgram", glUseProgram)) return false;
    if (!loadGLFunc("glUniformMatrix4fv", glUniformMatrix4fv)) return false;
    if (!loadGLFunc("glUniform1i", glUniform1i)) return false;
    if (!loadGLFunc("glUniform1f", glUniform1f)) return false;
    if (!loadGLFunc("glUniform2fv", glUniform2fv)) return false;
    if (!loadGLFunc("glUniform2f", glUniform2f)) return false;
    if (!loadGLFunc("glUniform3fv", glUniform3fv)) return false;
    if (!loadGLFunc("glUniform3f", glUniform3f)) return false;
    if (!loadGLFunc("glUniform4fv", glUniform4fv)) return false;
    if (!loadGLFunc("glUniform4f", glUniform4f)) return false;
    if (!loadGLFunc("glUniformMatrix2fv", glUniformMatrix2fv)) return false;
    if (!loadGLFunc("glUniformMatrix3fv", glUniformMatrix3fv)) return false;

    return render_init();
}
void OglCtx::cleanup() {
    if (this->hglrc) {
        wglMakeCurrent(nullptr, nullptr);
        wglDeleteContext(this->hglrc);
        this->hglrc = nullptr;
    }
    if (this->hdc && this->hwnd) {
        ReleaseDC(this->hwnd, this->hdc);
        this->hdc = nullptr;
        this->hwnd = NULL;
    }
}

void OglCtx::dump() {
    std::cout << "=== OpenGL Renderer Information ===" << std::endl;
    std::cout << "Vendor:       " << glGetString(GL_VENDOR) << std::endl;
    std::cout << "Renderer:     " << glGetString(GL_RENDERER) << std::endl;
    std::cout << "OpenGL Ver:   " << glGetString(GL_VERSION) << std::endl;

    // GLSL version (OpenGL 2.0+)
    const char* glsl_ver = (const char*)glGetString(GL_SHADING_LANGUAGE_VERSION);
    if (glsl_ver) {
        std::cout << "GLSL Ver:     " << glsl_ver << std::endl;
    } else {
        std::cout << "GLSL Ver:     (not available)" << std::endl;
    }

    // Extensions count (OpenGL 3.0+)
    if (this->glGetStringi) {
        GLint num_extensions = 0;
        glGetIntegerv(GL_NUM_EXTENSIONS, &num_extensions);
        std::cout << "Extensions:   " << num_extensions << std::endl;

        // Print first 10 extensions
        for (int i = 0; i < num_extensions && i < 10; i++) {
            const char* ext = (const char*)this->glGetStringi(GL_EXTENSIONS, (GLuint)i);
            if (ext) {
                std::cout << "  - " << ext << std::endl;
            }
        }
    } else {
        // Fallback for older OpenGL: print all extensions as a single string
        const char* exts = (const char*)glGetString(GL_EXTENSIONS);
        if (exts) {
            std::cout << "Extensions:   (legacy mode - " << strlen(exts) << " bytes)" << std::endl;
        }
    }

    // Print max texture size and viewport
    GLint max_tex_size = 0;
    glGetIntegerv(GL_MAX_TEXTURE_SIZE, &max_tex_size);
    std::cout << "Max Texture:  " << max_tex_size << "x" << max_tex_size << std::endl;

    GLint max_viewport[2] = {0, 0};
    glGetIntegerv(GL_MAX_VIEWPORT_DIMS, max_viewport);
    std::cout << "Max Viewport: " << max_viewport[0] << "x" << max_viewport[1] << std::endl;

    std::cout << "===================================" << std::endl;
}

void *tex_malloc(size_t size) {
    return dk2::MyHeap_alloc(size);
//    return heap_debug::malloc(size);
}
void tex_free(void *ptr) {
    dk2::MyHeap_free(ptr);
//    heap_debug::free(ptr);
}

bool g_oglInitialized = false;
OglCtx g_oglCtx;

size_t OglPatchTexture::release() {
    refs--;
    if(size_t result = refs) return result;
    if (GLuint textureId = this->textureId) {
        glDeleteTextures(1, &textureId);
        this->textureId = 0;
    }
    tex_free(this->data);
    delete this;
    return 0;
}

OglPatchTexture *OglPatchTexture::get(dk2::CEngineDDSurface &surf) {
    OglPatchTexture *obj = (OglPatchTexture *) surf.ddSurf;
    if(obj->magic != OglTexMagic) {
        throw std::exception("unexpected");
        return NULL;
    }
    return obj;
}

OglPatchTexture *OglPatchTexture::get(LPDIRECTDRAWSURFACE surf) {
    if(!surf) return NULL;
    auto *obj = (OglPatchTexture *) surf;
    if(obj->magic != OglTexMagic) {
        throw std::exception("unexpected");
        return NULL;
    }
    return obj;
}

int numberOfSetBits(uint32_t i) {
    i = i - ((i >> 1) & 0x55555555);        // add pairs of bits
    i = (i & 0x33333333) + ((i >> 2) & 0x33333333);  // quads
    i = (i + (i >> 4)) & 0x0F0F0F0F;        // groups of 8
    i *= 0x01010101;                        // horizontal sum of bytes
    return i >> 24;                         // return just that top byte (after truncating to 32-bit even when int is wider than uint32_t)
}

bool OglPatchTexture::copyToVideoMemory() {
    if (!this->textureId) return false;
    if (!this->isChanged) return true;
    glBindTexture(GL_TEXTURE_2D, this->textureId);

    // Set texture parameters
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
    glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);

    GLint textureWidth, textureHeight;
    glGetTexLevelParameteriv(GL_TEXTURE_2D, 0, GL_TEXTURE_WIDTH, &textureWidth);
    glGetTexLevelParameteriv(GL_TEXTURE_2D, 0, GL_TEXTURE_HEIGHT, &textureHeight);

    // Texture size must be power of two for the primitive OpenGL version this is written for. Find next power of two.
    size_t u2 = 1;
    while(u2 < this->width) u2 *= 2;
    size_t v2 = 1;
    while(v2 < this->height) v2 *= 2;

    // Make power of two version of the image.
//    dump_bgra32(data, width, height, width*4, "img");
    size_t src_pitch;
    if(this->bpp == 32) {
        src_pitch = this->width * 4;
    } else if(this->bpp == 16) {
        src_pitch = this->width * 2;
    } else {
        throw std::exception("unimplemented");
    }

    std::vector<unsigned char> image2(u2 * v2 * sizeof(uint32_t));
    auto *lineSrc = (uint8_t *) this->data;
    auto *lineDst = (uint8_t *) image2.data();
    for(size_t y = 0; y < this->height; y++) {
        for (size_t x = 0; x < this->width; x++) {
//                *(uint32_t *) &lineDst[x * 4] = *(uint32_t *) &lineSrc[x * 4];
            // BGRA -> RGBA
            dk2::Bgra color;
            if(this->bpp == 32) {
                auto *src = (uint8_t *) &lineSrc[x * 4];
                color.blue = src[0];
                color.green = src[1];
                color.red = src[2];
                color.alpha = src[3];
            } else {
                auto *src = (uint8_t *) &lineSrc[x * 2];
                color.blue = src[0];
                color.green = src[1];
                color.red = 0;
                color.alpha = 255;
            }
            auto *dst = (uint8_t *) &lineDst[x * 4];
            dst[0] = color.red;
            dst[1] = color.green;
            dst[2] = color.blue;
            dst[3] = color.alpha;
        }
        lineSrc += src_pitch;
        lineDst += u2 * 4;
    }
    this->u = (float) this->width / (float) u2;
    this->v = (float) this->height / (float) v2;

    // Upload texture data
    glTexImage2D(
            GL_TEXTURE_2D, 0, 4,
            u2, v2, 0, GL_RGBA, GL_UNSIGNED_BYTE, image2.data()
    );

    // Generate mipmaps (use function pointer if available)
    if (g_oglCtx.glGenerateMipmap) {
        g_oglCtx.glGenerateMipmap(GL_TEXTURE_2D);
    }

    glBindTexture(GL_TEXTURE_2D, 0);
    this->isChanged = false;
    return true;
}

