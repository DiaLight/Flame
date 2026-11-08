//
// Created by DiaLight on 5/31/2026.
//

#ifndef FLAME_OPENGL_INTERNAL_H
#define FLAME_OPENGL_INTERNAL_H


#include <windows.h>
#include <cstdint>
#include <gl/GL.h>
#include <GL/glext.h>
#include <GL/glu.h>
#include "dk2/CEngineDDSurface.h"
#include "dk2/MyDdSurface.h"

void PrintOpenGLInfo();

void *tex_malloc(size_t size);
void tex_free(void *ptr);

struct OglDebugCamera {
    float x     = 0.0f;
    float y     = 0.0f;
    float z     = 0.0f;

    float yaw   = 0.0f;  // Horizontal rotation (degrees)
    float pitch = 0.0f;  // Vertical rotation (degrees)
};

struct OglPatchTexture;
struct OglCtx {
    // Global window and OpenGL handles
    HWND hwnd = nullptr;
    HDC hdc = nullptr;
    HGLRC hglrc = nullptr;
    OglDebugCamera cam;

    // OpenGL utility functions
    PFNGLGETSTRINGIPROC glGetStringi = nullptr;
    PFNGLGENERATEMIPMAPPROC glGenerateMipmap = nullptr;
    PFNGLACTIVETEXTUREPROC glActiveTexture = nullptr;
    PFNGLCLIENTACTIVETEXTUREPROC glClientActiveTexture = nullptr;

    // Vertex array and buffer functions
    PFNGLGENVERTEXARRAYSPROC glGenVertexArrays = nullptr;
    PFNGLBINDVERTEXARRAYPROC glBindVertexArray = nullptr;
    PFNGLDELETEVERTEXARRAYSPROC glDeleteVertexArrays = nullptr;
    PFNGLGENBUFFERSPROC glGenBuffers = nullptr;
    PFNGLBINDBUFFERPROC glBindBuffer = nullptr;
    PFNGLDELETEBUFFERSPROC glDeleteBuffers = nullptr;
    PFNGLBUFFERDATAPROC glBufferData = nullptr;
    PFNGLVERTEXATTRIBPOINTERPROC glVertexAttribPointer = nullptr;
    PFNGLENABLEVERTEXATTRIBARRAYPROC glEnableVertexAttribArray = nullptr;
    PFNGLDISABLEVERTEXATTRIBARRAYPROC glDisableVertexAttribArray = nullptr;

    // Shader functions
    PFNGLCREATESHADERPROC glCreateShader = nullptr;
    PFNGLSHADERSOURCEPROC glShaderSource = nullptr;
    PFNGLCOMPILESHADERPROC glCompileShader = nullptr;
    PFNGLCREATEPROGRAMPROC glCreateProgram = nullptr;
    PFNGLLINKPROGRAMPROC glLinkProgram = nullptr;
    PFNGLATTACHSHADERPROC glAttachShader = nullptr;
    PFNGLDETACHSHADERPROC glDetachShader = nullptr;
    PFNGLDELETESHADERPROC glDeleteShader = nullptr;
    PFNGLDELETEPROGRAMPROC glDeleteProgram = nullptr;
    PFNGLGETSHADERIVPROC glGetShaderiv = nullptr;
    PFNGLGETSHADERINFOLOGPROC glGetShaderInfoLog = nullptr;
    PFNGLGETPROGRAMIVPROC glGetProgramiv = nullptr;
    PFNGLGETPROGRAMINFOLOGPROC glGetProgramInfoLog = nullptr;
    PFNGLGETUNIFORMLOCATIONPROC glGetUniformLocation = nullptr;
    PFNGLGETATTRIBLOCATIONPROC glGetAttribLocation = nullptr;
    PFNGLUSEPROGRAMPROC glUseProgram = nullptr;
    PFNGLUNIFORMMATRIX4FVPROC glUniformMatrix4fv = nullptr;
    PFNGLUNIFORM1IPROC glUniform1i = nullptr;
    PFNGLUNIFORM1FPROC glUniform1f = nullptr;
    PFNGLUNIFORM2FVPROC glUniform2fv = nullptr;
    PFNGLUNIFORM2FPROC glUniform2f = nullptr;
    PFNGLUNIFORM3FVPROC glUniform3fv = nullptr;
    PFNGLUNIFORM3FPROC glUniform3f = nullptr;
    PFNGLUNIFORM4FVPROC glUniform4fv = nullptr;
    PFNGLUNIFORM4FPROC glUniform4f = nullptr;
    PFNGLUNIFORMMATRIX2FVPROC glUniformMatrix2fv = nullptr;
    PFNGLUNIFORMMATRIX3FVPROC glUniformMatrix3fv = nullptr;

    bool init(HWND hWnd);
    void cleanup();

    void dump();

private:
    bool _init(HDC hdc);

};

// Global window and OpenGL handles
extern bool g_oglInitialized;
extern OglCtx g_oglCtx;

#define OglTexMagic 0x0617E810
struct OglPatchTexture {
    size_t refs = 1;
    uint32_t magic = OglTexMagic;
    size_t width;
    size_t height;
    size_t bpp;
    LPVOID data;
    float u = 1.f;
    float v = 1.f;
    GLuint textureId = 0;
    bool isChanged = true;
    DWORD srcColorKey = 0;

    static OglPatchTexture *get(dk2::CEngineDDSurface &surf);
    static OglPatchTexture *get(LPDIRECTDRAWSURFACE surf);
    static OglPatchTexture *get(LPDIRECTDRAWSURFACE4 surf) { return get((LPDIRECTDRAWSURFACE) surf); }
    static OglPatchTexture *get(dk2::MyDdSurface &surf) { return get(surf.dd_surface); }
    size_t release();

    bool copyToVideoMemory();
};



#endif //FLAME_OPENGL_INTERNAL_H
