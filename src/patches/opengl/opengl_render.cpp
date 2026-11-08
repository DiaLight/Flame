//
// Created by DiaLight on 6/18/2026.
//
#include "opengl_patch.h"
#include "dk2_globals.h"
#include "opengl_internal.h"
#include "tools/png_support.h"
#include "tools/visual_debug.h"
#include "patches/logging.h"
#include "imgui_impl_opengl3.h"
#include "imgui_impl_win32.h"
#include "dk2/engine/scene/RenderState_flags.h"
#include "ogl_debug_camera.h"
#include "ogl_render_utils.h"
#include "imgui_visual_debug.h"
#include "glm/glm.hpp"
#include "glm/gtc/matrix_transform.hpp"
#include "glm/gtc/type_ptr.hpp"
#include "ShaderProgram.h"
#include <exception>
#include <sstream>
#include <fstream>

#include "shader_sources.cpp"
#include "visual_value.h"


ShaderProgram g_shaderProgram;

bool render_init() {

    // Initialize shader program with embedded sources
    if (!g_shaderProgram.loadFromStrings(
            shaders::VertexShaderSource(),
            shaders::FragmentShaderSource())) {
        patch::log::err("Failed to load shader program!");
        return false;
    }

    return true;
}


void SetTexStageCombine(GLenum unit,
                        GLenum rgbCombine, GLenum src0RGB, GLenum src1RGB,
                        GLenum alphaCombine, GLenum src0Alpha, GLenum src1Alpha)
{
    g_oglCtx.glActiveTexture(unit);
    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);

    glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB,   rgbCombine);
    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB,   src0RGB);
    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE1_RGB,   src1RGB);
    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND0_RGB,  GL_SRC_COLOR);
    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND1_RGB,  GL_SRC_COLOR);

    glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA,   alphaCombine);
    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA,   src0Alpha);
    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE1_ALPHA,   src1Alpha);
    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND0_ALPHA,  GL_SRC_ALPHA);
    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND1_ALPHA,  GL_SRC_ALPHA);
}

inline DWORD F2DW( FLOAT f ) { return *((DWORD*)&f); }

void enableBumpmap(uint32_t enabledFlags) {
    IDirect3DDevice3 *dev = dk2::MyDirectDraw_instance_triangles.d3d3_halDevice;

//    dev->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
//    dev->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
//    dev->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
//
//    dev->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
//    dev->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
//    dev->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);


    // Stage 0: MODULATE(TEXTURE, DIFFUSE)
    g_oglCtx.glActiveTexture(GL_TEXTURE0);

    glTexEnvf (GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE_EXT);
    glTexEnvf (GL_TEXTURE_ENV, GL_COMBINE_RGB_EXT, GL_REPLACE);

//    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);
//
//    // RGB
//    glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB,   GL_MODULATE);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB,   GL_TEXTURE);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE1_RGB,   GL_PRIMARY_COLOR);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND0_RGB,  GL_SRC_COLOR);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND1_RGB,  GL_SRC_COLOR);
//
//    // Alpha
//    glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA,   GL_MODULATE);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA,   GL_TEXTURE);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE1_ALPHA,   GL_PRIMARY_COLOR);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND0_ALPHA,  GL_SRC_ALPHA);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND1_ALPHA,  GL_SRC_ALPHA);



    // Stage 1: BUMPENVMAP(TEXTURE, CURRENT)  [alpha disabled]
    g_oglCtx.glActiveTexture(GL_TEXTURE1);

    glTexEnvf (GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE_EXT);
    glTexEnvf (GL_TEXTURE_ENV, GL_COMBINE_RGB_EXT, GL_ADD);

//    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);
//
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB, GL_TEXTURE);
//    glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB, GL_DOT3_RGB);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE1_RGB, GL_PREVIOUS);

//    // RGB: MODULATE(TEX, PREV)
//    glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB,   GL_MODULATE);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB,   GL_TEXTURE);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE1_RGB,   GL_PREVIOUS);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND0_RGB,  GL_SRC_COLOR);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND1_RGB,  GL_SRC_COLOR);

//    // Alpha: pass through previous
//    glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA,   GL_REPLACE);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA,   GL_PREVIOUS);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE1_ALPHA,   GL_PREVIOUS);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND0_ALPHA,  GL_SRC_ALPHA);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND1_ALPHA,  GL_SRC_ALPHA);



//    // Stage 2: ADD(TEXTURE, CURRENT)  [alpha disabled]
//    g_oglCtx.glActiveTexture(GL_TEXTURE2);
//    glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_COMBINE);
//
//    // RGB: ADD(TEX, PREV)
//    glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB,   GL_ADD);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_RGB,   GL_TEXTURE);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE1_RGB,   GL_PREVIOUS);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND0_RGB,  GL_SRC_COLOR);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND1_RGB,  GL_SRC_COLOR);
//
//    // Alpha: pass through previous
//    glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA,   GL_REPLACE);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE0_ALPHA,   GL_PREVIOUS);
//    glTexEnvi(GL_TEXTURE_ENV, GL_SOURCE1_ALPHA,   GL_PREVIOUS);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND0_ALPHA,  GL_SRC_ALPHA);
//    glTexEnvi(GL_TEXTURE_ENV, GL_OPERAND1_ALPHA,  GL_SRC_ALPHA);


//    if ((enabledFlags & RenderState_bumpMapSimple) != 0) {
//        dev->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_BUMPENVMAP);
//        dev->SetTextureStageState(1, D3DTSS_COLORARG1, D3DTA_TEXTURE);
//        dev->SetTextureStageState(1, D3DTSS_COLORARG2, D3DTA_CURRENT);
//    }
//    if ((enabledFlags & RenderState_bumpMapLuminance) != 0) {
//        dev->SetTextureStageState(1, D3DTSS_COLOROP, D3DTOP_BUMPENVMAPLUMINANCE);
//        dev->SetTextureStageState(1, D3DTSS_COLORARG1, D3DTA_TEXTURE);
//        dev->SetTextureStageState(1, D3DTSS_COLORARG2, D3DTA_CURRENT);
//    }

//    dev->SetTextureStageState(1, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
//    dev->SetTextureStageState(1, D3DTSS_BUMPENVMAT00, F2DW(1.0f));
//    dev->SetTextureStageState(1, D3DTSS_BUMPENVMAT01, F2DW(0.0f));
//    dev->SetTextureStageState(1, D3DTSS_BUMPENVMAT10, F2DW(0.0f));
//    dev->SetTextureStageState(1, D3DTSS_BUMPENVMAT11, F2DW(1.0f));
//
//    dev->SetTextureStageState(1, D3DTSS_BUMPENVLSCALE, F2DW(1.0f));
//    dev->SetTextureStageState(1, D3DTSS_BUMPENVLOFFSET, F2DW(0.0f));
//
//
//    dev->SetTextureStageState(2, D3DTSS_COLORARG1, D3DTA_TEXTURE);
//    dev->SetTextureStageState(2, D3DTSS_COLORARG2, D3DTA_CURRENT);
//    dev->SetTextureStageState(2, D3DTSS_COLOROP, D3DTOP_ADD);
//
//    dev->SetTextureStageState(2, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
}
void patch::opengl_patch::updateTexRenderState(uint32_t flags) {
    unsigned int texStage = dk2::g_texStage;
    IDirect3DDevice3 *dev = dk2::MyDirectDraw_instance_triangles.d3d3_halDevice;

    static VisualBool ogl_disableDepthFlags("ogl.disableDepthFlags");
    static VisualBool ogl_disableBlendFlags("ogl.disableBlendFlags");

    // --- Handle features that were disabled ---
    int disabledFlags = dk2::g_mgsr_currentDrawFlags & ~flags;
    if (disabledFlags) {
        // Multitexture combiner disabled
        if ((disabledFlags & (RenderState_bumpMapLuminance | RenderState_bumpMapSimple)) != 0) {
//            dev->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
//            dev->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
//            dev->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
//
//            dev->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
//            dev->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
//            dev->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);

            g_oglCtx.glActiveTexture(GL_TEXTURE0);
            glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
            glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB, GL_MODULATE);
            glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA, GL_MODULATE);

            texStage = 1;
        }
        // Non-blended
        constexpr uint32_t blendFlags = RenderState_alphaBlendInvSrc | RenderState_alphaBlendSrc | RenderState_fl2 | RenderState_alphaBlendOne;
        static_assert(blendFlags == 0x1023);
        if ((disabledFlags & blendFlags) != 0 && (flags & blendFlags) == 0) {
//            dev->SetRenderState(D3DRENDERSTATE_DESTBLEND, D3DBLEND_ZERO);
//            dev->SetRenderState(D3DRENDERSTATE_SRCBLEND, D3DBLEND_ONE);
//            dev->SetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, 0);
            if(!ogl_disableBlendFlags) {
                glBlendFunc(GL_SRC_ALPHA, GL_ONE);
                glBlendFunc(GL_DST_ALPHA, GL_ZERO);
                glDisable(GL_BLEND);
            }
        }
        // Alpha op changed
        if ((disabledFlags & RenderState_diffuseAlpha) != 0) {
            dev->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
            dev->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_CURRENT);
            dev->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
        }
        // Z-write disable
        if ((disabledFlags & RenderState_zWriteEnable) != 0) {
//            dev->SetRenderState(D3DRENDERSTATE_ZWRITEENABLE, 0);
            if(!ogl_disableDepthFlags) {
                glDepthMask(GL_FALSE);
            }
        }
        // Z-enable disable
        if ((disabledFlags & RenderState_zEnable) != 0) {
//            dev->SetRenderState(D3DRENDERSTATE_ZENABLE, 0);
            if(!ogl_disableDepthFlags) {
                glDisable(GL_DEPTH_TEST);
            }
        }
        // Point sampling
        if ((disabledFlags & RenderState_linearFiltering) != 0) {
//            for (int i = 0; i < dk2::MyDirectDraw_instance_triangles.texturesCount; ++i) {
//                dev->SetTextureStageState(i, D3DTSS_MAGFILTER, 1);
//                dev->SetTextureStageState(i, D3DTSS_MINFILTER, 1);
//            }
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
        }
    }
    // --- Handle features that were enabled ---
    int enabledFlags = ~dk2::g_mgsr_currentDrawFlags & flags;
    if (enabledFlags) {
        // Alpha blending (standard)
        if ((enabledFlags & RenderState_alphaBlendOne) != 0) {
            if(!ogl_disableBlendFlags) {
                glBlendFunc(GL_SRC_ALPHA, GL_ONE);
                glBlendFunc(GL_DST_ALPHA, GL_ONE);
                glEnable(GL_BLEND);
            }
//            dev->SetRenderState(D3DRENDERSTATE_SRCBLEND, D3DBLEND_ONE);
//            dev->SetRenderState(D3DRENDERSTATE_DESTBLEND, D3DBLEND_ONE);
//            dev->SetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, 1);
        }
        // Alpha blending (variant)
        if ((enabledFlags & RenderState_alphaBlendSrc) != 0) {
            if(!ogl_disableBlendFlags) {
                glBlendFunc(GL_SRC_ALPHA, GL_SRC_ALPHA);
                glBlendFunc(GL_DST_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
                glEnable(GL_BLEND);
            }
//            dev->SetRenderState(D3DRENDERSTATE_SRCBLEND, D3DBLEND_SRCALPHA);
//            dev->SetRenderState(D3DRENDERSTATE_DESTBLEND, D3DBLEND_INVSRCALPHA);
//            dev->SetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, 1);
        }
        // Alpha op change
        if ((enabledFlags & RenderState_diffuseAlpha) != 0) {
            dev->SetTextureStageState(0, D3DTSS_ALPHAARG1, 0);
            dev->SetTextureStageState(0, D3DTSS_ALPHAARG2, 1);
            dev->SetTextureStageState(0, D3DTSS_ALPHAOP, 2);
        }
        // Alpha blending (another variant)
        if ((enabledFlags & RenderState_alphaBlendInvSrc) != 0) {
//            dev->SetRenderState(D3DRENDERSTATE_SRCBLEND, D3DBLEND_ZERO);
//            dev->SetRenderState(D3DRENDERSTATE_DESTBLEND, D3DBLEND_INVSRCCOLOR);
//            dev->SetRenderState(D3DRENDERSTATE_ALPHABLENDENABLE, 1);
            if(!ogl_disableBlendFlags) {
                glBlendFunc(GL_SRC_ALPHA, GL_ZERO);
                glBlendFunc(GL_DST_ALPHA, GL_ONE_MINUS_SRC_COLOR);
                glEnable(GL_BLEND);
            }
        }
        // Z-write enable
        if ((enabledFlags & RenderState_zWriteEnable) != 0) {
            if(!ogl_disableDepthFlags) {
                glDepthMask(GL_TRUE);
            }
        }
        // Z-enable
        if ((enabledFlags & RenderState_zEnable) != 0) {
            if(!ogl_disableDepthFlags) {
                glEnable(GL_DEPTH_TEST);
                glDepthFunc(GL_LEQUAL);  // we need equal because DK2 is rendering block highlight triangles in exact same place as block triangles
            }
        }
        // Linear filtering
        if ((enabledFlags & RenderState_linearFiltering) != 0) {
//            for (int j = 0; j < dk2::MyDirectDraw_instance_triangles.texturesCount; ++j) {
//                dev->SetTextureStageState(j, D3DTSS_MAGFILTER, 2);
//                dev->SetTextureStageState(j, D3DTSS_MINFILTER, 2);
//            }
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        }
        if (((enabledFlags & (RenderState_bumpMapSimple | RenderState_bumpMapLuminance)) != 0)) {
            enableBumpmap(enabledFlags);
            texStage = 1;
        }
    }

    // Disable extra stages
    for (int i = texStage; i < dk2::g_texStage; ++i) {
//        dev->SetTextureStageState(i, D3DTSS_COLOROP, D3DTOP_DISABLE);
//        dev->SetTextureStageState(i, D3DTSS_ALPHAOP, D3DTOP_DISABLE);
        g_oglCtx.glActiveTexture(GL_TEXTURE0 + i);
//        glTexEnvi(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_MODULATE);
//        glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB, GL_MODULATE);
//        glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA, GL_MODULATE);
        glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_RGB, GL_REPLACE);
        glTexEnvi(GL_TEXTURE_ENV, GL_COMBINE_ALPHA, GL_REPLACE);
    }

    // Update state
    dk2::g_texStage = texStage;
    dk2::g_mgsr_currentDrawFlags = flags;
}


static int g_texcur = 0;
static float g_scaleImage = 1.f;

void patch::opengl_patch::beginScene() {
    TickOglCamera();

    glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
    glColor4ub(255, 255, 255, 255);

    GLint viewport[4];
    glGetIntegerv(GL_VIEWPORT, viewport);
    GLdouble winWidth = (GLdouble) viewport[2];
    GLdouble winHeight = (GLdouble) viewport[3];
    GLfloat aspect = winWidth / winHeight;

//    glm::mat4 projection = glm::perspective(glm::radians(60.0f), (float)winWidth / (float)winHeight, 0.1f, 100.0f);
//    glm::mat4 view = GetViewMatrix();
//
//    view = glm::scale(view, glm::vec3(1, -1, 1));  // inert Y
//    static VisualBool disableSoftwarePerspective("ogl.disableSoftwarePerspective gl");
//    if (disableSoftwarePerspective) {
//        view = glm::scale(view, glm::vec3(1, 1, -1));  // inert Z
//    } else {
//        view = glm::translate(view, glm::vec3(0, 0, -1));
//        view = glm::scale(view, glm::vec3(2, 2, 1));
//
////            view = glm::translate(view, glm::vec3(-.5f * (640.f / winWidth), -.5f * (480.f / winHeight), 0));
//
//        view = glm::scale(view, glm::vec3(1, 1, -1));  // inert Z
//
//        view = glm::scale(view, glm::vec3(1. / winWidth, 1. / winHeight, 1));
//        view = glm::translate(view, glm::vec3(-640.f / 2, -480.f / 2, 0));
//    }

    glLoadMatrixf(glm::value_ptr(GetViewMatrix()));
    glScaled(1, -1, 1);  // inert Y

    static VisualBool disableSoftwarePerspective("ogl.disableSoftwarePerspective gl");
    if (disableSoftwarePerspective) {
        glScaled(1, 1, -1);  // inert Z
    } else {
        glTranslatef(0, 0, -1);
        glScaled(2, 2, 1);

        //    glTranslatef(-.5f * (640.f / winWidth), -.5f * (480.f / winHeight), 0);

        glScaled(1, 1, -1);  // inert Z

        glScaled(1. / winWidth, 1. / winHeight, 1);
        glTranslatef(-640.f / 2, -480.f / 2, 0);
    }


    glEnableClientState(GL_VERTEX_ARRAY);
    glEnableClientState(GL_COLOR_ARRAY);

    for (int i = 0; i < 3; ++i) {
        g_oglCtx.glClientActiveTexture(GL_TEXTURE0 + i);
        glEnableClientState(GL_TEXTURE_COORD_ARRAY);
        g_oglCtx.glActiveTexture(GL_TEXTURE0 + i);
        glEnable(GL_TEXTURE_2D);
    }

    g_texcur = 0;

    if(patch::opengl_patch::enableImgui) {
        // Start the Dear ImGui frame
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        ImGui::Begin("Texture");
        ImGui::SliderFloat("scale", &g_scaleImage, 1.0, 4.0);
    }
}

inline dk2::MyD3D3Vertex *getVertex(const dk2::MyD3D3Vertex *vertices, size_t vertexSize, size_t idx) {
    return (dk2::MyD3D3Vertex *) ((char *) vertices + vertexSize * idx);
}
inline ImVec2 getUvPos(dk2::RenderStageTex *const *textures, const dk2::MyD3D3Vertex *vert, size_t idx) {
    auto *oglTex = OglPatchTexture::get(*(dk2::CEngineDDSurface *) textures[idx]->surf);
    return ImVec2 {(vert->tex[idx].u * oglTex->width), (vert->tex[idx].v * oglTex->height)};
}

inline void drawUvLine(
        ImVec2 offset, float scale,
        const dk2::MyD3D3Vertex *vertices, size_t vertexSize,
        dk2::RenderStageTex *const *textures,
        size_t fr, size_t to, size_t tex, ImU32 col) {
    ImVec2 tp1 = getUvPos(textures, getVertex(vertices, vertexSize, fr), tex);
    ImVec2 tp2 = getUvPos(textures, getVertex(vertices, vertexSize, to), tex);
    {
        ImVec2 d = (tp2 - tp1) * 0.1f;
        tp1 = tp1 + d;
        tp2 = tp2 - d;
    }
    ImGui::GetWindowDrawList()->AddLine(offset + tp1 * scale, offset + tp2 * scale, col);
};

void patch::opengl_patch::drawCall(
        uint32_t renderStateFlags,
        dk2::RenderStageTex *const *textures, size_t texturesCount,
        const dk2::MyD3D3Vertex *vertices, size_t vertexSize, size_t verticesCount,
        const dk2::Idx3us *indices, size_t trianglesCount
) {
    updateTexRenderState(renderStateFlags);
    if(texturesCount > dk2::MyDirectDraw_instance_triangles.texturesCount) throw std::exception("tex overflow");

    static VisualInt _skip("tex.skip", 0);
    static VisualInt _limit("tex.limit", 3);


    if(patch::opengl_patch::enableImgui && texturesCount > 1) {  // patch
        size_t texcur = g_texcur;
        {  // patch
            static VisualInt _skip("draw_call.skip", 0);
            if(texcur < _skip.value) return;
            static VisualInt _limit("draw_call.limit", 15);
            if(texcur >= _limit.value) return;
        }
    }
    static VisualBool useAlpha("ogl.use alpha");
    size_t colorSize = 3;
    if(useAlpha) colorSize = 4;

    if (((renderStateFlags & (RenderState_bumpMapSimple | RenderState_bumpMapLuminance)) != 0)) {  // special rendering
        g_shaderProgram.use();

        {
            glm::mat4 projection;
            glm::mat4 view;
            glGetFloatv(GL_PROJECTION_MATRIX, glm::value_ptr(projection));
            glGetFloatv(GL_MODELVIEW_MATRIX, glm::value_ptr(view));

            glm::mat4 model = glm::mat4(1.0f);
            glm::mat4 mvp = projection * view * model;

            // Pass MVP uniform
            g_shaderProgram.setMat4("u_mvp", mvp);
        }

        if(texturesCount != 3) throw std::exception("invalid texture count");

        auto loadTexture = [](dk2::RenderStageTex *tex, GLenum texture, const std::string &name, GLint v0) -> void {
            auto *oglTex = OglPatchTexture::get(*(dk2::CEngineDDSurface *) tex->surf);
            oglTex->copyToVideoMemory();
            if (!oglTex->textureId) throw std::exception("software texture");
            g_oglCtx.glActiveTexture(texture);
            glBindTexture(GL_TEXTURE_2D, oglTex->textureId);
            g_shaderProgram.setInt(name, v0);
        };
        loadTexture(textures[0], GL_TEXTURE0, "u_texture", 0);
        loadTexture(textures[1], GL_TEXTURE1, "u_heightMap", 1);
        loadTexture(textures[2], GL_TEXTURE2, "u_background", 2);

        // Set bump scale (adjust for desired bump intensity)
        g_shaderProgram.setFloat("u_bumpScale", 0.1f);

        // Position attribute (location 0)
        g_oglCtx.glVertexAttribPointer(0, 3, GL_FLOAT, GL_FALSE, vertexSize, (const GLbyte*)vertices + offsetof(dk2::MyD3D3Vertex, vec));
        g_oglCtx.glEnableVertexAttribArray(0);

        // Texture coordinate attribute (location 1)
        g_oglCtx.glVertexAttribPointer(1, 2, GL_FLOAT, GL_FALSE, vertexSize, (const GLbyte*)vertices + offsetof(dk2::MyD3D3Vertex, tex) + sizeof(dk2::TexCoord) * 0);
        g_oglCtx.glEnableVertexAttribArray(1);

        // Height mapping coordinate attribute (location 2)
        g_oglCtx.glVertexAttribPointer(2, 2, GL_FLOAT, GL_FALSE, vertexSize, (const GLbyte*)vertices + offsetof(dk2::MyD3D3Vertex, tex) + sizeof(dk2::TexCoord) * 1);
        g_oglCtx.glEnableVertexAttribArray(2);

        // Height mapping coordinate attribute (location 3)
        g_oglCtx.glVertexAttribPointer(3, 2, GL_FLOAT, GL_FALSE, vertexSize, (const GLbyte*)vertices + offsetof(dk2::MyD3D3Vertex, tex) + sizeof(dk2::TexCoord) * 2);
        g_oglCtx.glEnableVertexAttribArray(3);

        // Light attribute (location 4)
        g_oglCtx.glVertexAttribPointer(4, colorSize, GL_FLOAT, GL_FALSE, vertexSize, (const GLbyte*)vertices + offsetof(dk2::MyD3D3Vertex, diffuse));
        g_oglCtx.glEnableVertexAttribArray(4);

    } else {  // regular rendering

        glVertexPointer(3, GL_FLOAT, vertexSize, (const GLbyte*)vertices + offsetof(dk2::MyD3D3Vertex, vec));

        glColorPointer(colorSize, GL_UNSIGNED_BYTE, vertexSize, (const GLbyte*)vertices + offsetof(dk2::MyD3D3Vertex, diffuse));


        for (int i = 0; i < texturesCount; ++i) {
            if(texturesCount > 1) {  // patch
                if(i < _skip.value) continue;
                if(i >= _limit.value) break;
            }

            auto *oglTex = OglPatchTexture::get(*(dk2::CEngineDDSurface *) textures[i]->surf);
            oglTex->copyToVideoMemory();
            if (!oglTex->textureId) throw std::exception("software texture");

            // Select the texture unit (equivalent to SetTexture stage)
            g_oglCtx.glActiveTexture(GL_TEXTURE0 + i);
            // Bind the texture (equivalent to passing pTexture)
            glBindTexture(GL_TEXTURE_2D, oglTex->textureId);
        }


        for (int i = 0; i < texturesCount; ++i) {
            if (texturesCount > 1) {  // patch
                if (i < _skip.value) continue;
                if (i >= _limit.value) break;
            }

            auto *oglTex = OglPatchTexture::get(*(dk2::CEngineDDSurface *) textures[i]->surf);
            oglTex->copyToVideoMemory();
            if (!oglTex->textureId) throw std::exception("software texture");

            // Select the texture unit (equivalent to SetTexture stage)
            g_oglCtx.glClientActiveTexture(GL_TEXTURE0 + i);
            glTexCoordPointer(2, GL_FLOAT, vertexSize, (const GLbyte*)vertices + offsetof(dk2::MyD3D3Vertex, tex) + sizeof(dk2::TexCoord) * i);
        }
//        g_oglCtx.glActiveTexture(GL_TEXTURE0); // back to unit 0
    }

    glDrawElements(GL_TRIANGLES, 3 * trianglesCount, GL_UNSIGNED_SHORT, indices);

    if (((renderStateFlags & (RenderState_bumpMapSimple | RenderState_bumpMapLuminance)) != 0)) {
        g_oglCtx.glUseProgram(0);
    }
    // cleanup
    for (int i = 0; i < texturesCount; ++i) {
        g_oglCtx.glActiveTexture(GL_TEXTURE0 + i);
        glBindTexture(GL_TEXTURE_2D, 0);
    }

    bool _open = false;
    if(patch::opengl_patch::enableImgui && texturesCount > 1) {  // patch
        size_t texcur = g_texcur;
        g_texcur++;
        if (ImGui::TreeNode((void *) texcur, "tex_%d", texcur)) {
            ImGui::Text("texturesCount %d", texturesCount);
            ImGui::Text("trianglesCount %d", trianglesCount);
            ImGui::Text("flags: %08X", renderStateFlags);
            _open = true;
        }
    }
    for (int i = 0; i < texturesCount; ++i) {
        if(texturesCount > 1) {  // patch
            if(i < _skip.value) continue;
            if(i >= _limit.value) break;
        }
        auto *oglTex = OglPatchTexture::get(*(dk2::CEngineDDSurface *) textures[i]->surf);
        if(_open) {  // patch
            ImGui::Text("size = %d x %d", oglTex->width, oglTex->height);
            ImVec2 offset = ImGui::GetWindowPos() + ImGui::GetCursorPos() - ImVec2(ImGui::GetScrollX(), ImGui::GetScrollY());
            ImGui::Image((ImTextureID)(intptr_t)oglTex->textureId, ImVec2(oglTex->width, oglTex->height) * g_scaleImage);

            for (int j = 0; j < trianglesCount; ++j) {
                auto &tri = indices[j];
                drawUvLine(offset, g_scaleImage, vertices, vertexSize, textures, tri.i, tri.j, i, ImColor(1.f, 1.f / j, 0.f));
                drawUvLine(offset, g_scaleImage, vertices, vertexSize, textures, tri.j, tri.k, i, ImColor(1.f, 1.f / j, 0.f));
                drawUvLine(offset, g_scaleImage, vertices, vertexSize, textures, tri.k, tri.i, i, ImColor(1.f, 1.f / j, 0.f));
            }
        }
    }

    if(_open) {
        if((1 << 15) & GetAsyncKeyState(VK_NUMPAD1)) {
            char tmp[256];

            static std::string lastResult;
            std::string result;
            {
                std::stringstream ss;
                for (int j = 0; j < trianglesCount; ++j) {
                    snprintf(tmp, sizeof tmp, "%d, %d, %d\n", indices[j].i, indices[j].j, indices[j].k);
                    ss << tmp;
                }
                result = ss.str();
            }

            if(result != lastResult) {
                static int num = 0;
                snprintf(tmp, sizeof tmp, "D:\\Share\\idx_%d.txt", num++);
                std::ofstream of(tmp);
                of << result;
                lastResult = result;
            }
        }
    }
    if(patch::opengl_patch::enableImgui) {  // patch
        if(_open) ImGui::TreePop();
    }
}


void patch::opengl_patch::endScene() {
    for (int i = 0; i < 3; ++i) {
        g_oglCtx.glActiveTexture(GL_TEXTURE0 + i);
        glDisable(GL_TEXTURE_2D);
        g_oglCtx.glClientActiveTexture(GL_TEXTURE0 + i);
        glDisableClientState(GL_TEXTURE_COORD_ARRAY);
    }
    glDisableClientState(GL_COLOR_ARRAY);
    glDisableClientState(GL_VERTEX_ARRAY);

    if(patch::opengl_patch::enableImgui) {
        ImGui::End();

        patch::opengl_patch::imgui_tick();

        // Rendering
        ImGui::Render();

        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
    }
}

void patch::opengl_patch::flip() {
    if(dk2::MyDdSurfaceEx *surf = dk2::MyWindow_instance.getCurOffScreenSurf()) {
        static VisualBool use2d("ogl.frontend 2d");

        GLfloat projMatrix[16];
        GLfloat modelviewMatrix[16];

        GLint viewport[4];
        glGetIntegerv(GL_VIEWPORT, viewport);
        float winWidth = (float) viewport[2];
        float winHeight = (float) viewport[3];
        GLfloat aspect = winWidth / winHeight;

        if(use2d) {
            // Save current matrices
            SaveMatrices(projMatrix, modelviewMatrix);

            // Set up orthographic projection for 2D screen-space rendering
            Setup2DProjection(winWidth, winHeight);

            // Enable blending for smooth GUI rendering
            dk2::g_texStage = 1;
            updateTexRenderState(RenderState_alphaBlendSrc);
        } else {
            dk2::g_texStage = 1;
            updateTexRenderState(RenderState_linearFiltering | RenderState_zEnable | RenderState_zWriteEnable | RenderState_useLightSplat | RenderState_alphaBlendSrc);

            glLoadMatrixf(glm::value_ptr(GetViewMatrix()));
//            glLoadIdentity();
            glTranslatef(0.0f, 0.0f, -0.9f);

            glScalef(1.f * aspect, 1.f, 1.f);
            GLfloat scale = 0.5f;
            glScalef(scale, scale, 1.f);
        }

        renderGuiSurf(*surf);


        if(use2d) {
            // Restore matrices
            RestoreMatrices(projMatrix, modelviewMatrix);
        }
    }

    if(patch::opengl_patch::enableImgui) {
//        ImVec4 clear_color = ImVec4(0.45f, 0.55f, 0.60f, 1.00f);
//        glViewport(0, 0, g_Width, g_Height);
//        glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
//        glClear(GL_COLOR_BUFFER_BIT);
    }
    SwapBuffers(g_oglCtx.hdc);
}
