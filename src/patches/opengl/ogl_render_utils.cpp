//
// Created by DiaLight on 8/4/2026.
//

#include "ogl_render_utils.h"
#include "opengl_patch.h"
#include "dk2_globals.h"
#include "opengl_internal.h"
#include "tools/visual_debug.h"
#include "patches/logging.h"
#include "imgui_impl_opengl3.h"
#include "imgui_impl_win32.h"


void patch::opengl_patch::renderGuiSurf(dk2::MyDdSurfaceEx &surf) {

    auto &oglTex = *OglPatchTexture::get(surf.dd_surf);
//    {  // debug texture width
//        size_t dst_pitch = oglTex.width * 4;
//        auto *dline = (uint8_t *) oglTex.data;
//        for (int dy = 0; dy < oglTex.height; ++dy) {
//            auto *dpos = (uint32_t *) (dline);
//            dpos[oglTex.width - 1] = 0xFFFF00FF;
//            dline += dst_pitch;
//        }
//    }

    oglTex.copyToVideoMemory();
    if (!oglTex.textureId) throw std::exception("software texture");
    g_oglCtx.glActiveTexture(GL_TEXTURE0);
    glBindTexture(GL_TEXTURE_2D, oglTex.textureId);


    static const dk2::MyD3D3Vertex squareVertices[] = {
            {-1.f,  1.0f,  0.0f, 1.0f, (int) 0xFFFFFFFF, {0.0f, 0.0f}},  // red
            {-1.f, -1.0f,  0.0f, 1.0f, (int) 0xFFFFFFFF, {0.0f, oglTex.v}},  // green
            { 1.f, -1.0f,  0.0f, 1.0f, (int) 0xFFFFFFFF, {oglTex.u, oglTex.v}},  // blue
            { 1.f,  1.0f,  0.0f, 1.0f, (int) 0xFFFFFFFF, {oglTex.u, 0.0f}},
    };

    static const GLuint squareIndices[] = {
            0, 1, 3,  // First triangle (top-left, bottom-left, top-right)
            3, 1, 2,  // Second triangle (top-right, bottom-left, bottom-right)
    };

    g_oglCtx.glClientActiveTexture(GL_TEXTURE0);
    glEnableClientState(GL_VERTEX_ARRAY);
    glEnableClientState(GL_COLOR_ARRAY);
    glEnableClientState(GL_TEXTURE_COORD_ARRAY);
    glEnable(GL_TEXTURE_2D);

    glVertexPointer(2, GL_FLOAT, sizeof(dk2::MyD3D3Vertex), (const GLbyte*) squareVertices + offsetof(dk2::MyD3D3Vertex, vec));
    glColorPointer(4, GL_UNSIGNED_BYTE, sizeof(dk2::MyD3D3Vertex), (const GLbyte*) squareVertices + offsetof(dk2::MyD3D3Vertex, diffuse));
    glTexCoordPointer(2, GL_FLOAT, sizeof(dk2::MyD3D3Vertex), (const GLbyte*) squareVertices + offsetof(dk2::MyD3D3Vertex, tex));

    glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_INT, squareIndices);

    glDisable(GL_TEXTURE_2D);
    glDisableClientState(GL_TEXTURE_COORD_ARRAY);
    glDisableClientState(GL_COLOR_ARRAY);
    glDisableClientState(GL_VERTEX_ARRAY);

    {  // debug borders
        float savedWidth;
        glGetFloatv(GL_LINE_WIDTH, &savedWidth);  // save current
        glLineWidth(2.0f);

        glBegin(GL_LINE_LOOP);
        glColor3f(1.0f, 0.0f, 0.0f); glVertex3f(-1.0f, 1.0f, 0.0f);
        glColor3f(0.0f, 1.0f, 0.0f); glVertex3f(-1.0f, -1.0f, 0.0f);
        glColor3f(0.0f, 0.0f, 1.0f); glVertex3f(1.0f, -1.0f, 0.0f);
        glColor3f(0.0f, 1.0f, 1.0f); glVertex3f(1.0f, 1.0f, 0.0f);
        glEnd();

        glBegin(GL_LINES);
        glColor3f(1.0f, 0.0f, 0.0f); glVertex3f(0.0f, 1.0f, 0.0f);
        glColor3f(0.0f, 0.0f, 1.0f); glVertex3f(0.0f, -1.0f, 0.0f);

        glColor3f(0.0f, 0.0f, 1.0f); glVertex3f(1.0f, 0.0f, 0.0f);
        glColor3f(0.0f, 1.0f, 0.0f); glVertex3f(-1.0f, 0.0f, 0.0f);
        glEnd();

        glLineWidth(savedWidth);  // restore previous
    }
}
