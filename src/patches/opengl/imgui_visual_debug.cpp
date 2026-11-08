//
// Created by DiaLight on 6/30/2026.
//
#include "imgui_visual_debug.h"
#include "dk2_globals.h"
#include "dk2_functions.h"

#include "opengl_internal.h"
#include "imgui.h"
#include "dk2/math/q12_utils.h"
#include "opengl_patch.h"
#include "dk2/engine/game_engine.h"
#include "dk2/MyWindow.h"
#include "tools/visual_debug.h"
#include "visual_value.h"

#include <sstream>
#include <map>


namespace ImGui {

    bool DragQ12(const char* label, dk2::Q12 &v, float v_speed = 0.1f, int v_min = 0, int v_max = 0, const char* format = "%.3f", ImGuiSliderFlags flags = 0) {
        // If v_min >= v_max we have no bound
        float value = dk2::Q12_decode(v);
        if(DragFloat(label, &value, v_speed, v_min, v_max, format, flags)) {
            v = dk2::Q12_encode(value);
            return true;
        }
        return false;
    }
    bool DragMat3x3f(const char* label, dk2::Mat3x3f &v, float v_speed = 0.1f, int v_min = 0, int v_max = 0, const char* format = "%.3f", ImGuiSliderFlags flags = 0) {
        bool result = false;
        char text[256];
        strcpy(text, label);
        char *pos = text + strlen(text);
        strcpy(pos, "[0]");
        if(DragFloat(text, v.m[0], v_speed, v_min, v_max, format, flags)) result = true;
        strcpy(pos, "[1]");
        if(DragFloat(text, v.m[1], v_speed, v_min, v_max, format, flags)) result = true;
        strcpy(pos, "[2]");
        if(DragFloat(text, v.m[2], v_speed, v_min, v_max, format, flags)) result = true;
        return result;
    }
    bool DragVec3q12(const char* label, dk2::Vec3q12 &v, float v_speed = 0.1f, int v_min = 0, int v_max = 0, const char* format = "%.3f", ImGuiSliderFlags flags = 0) {
//        ImGui::PushID(label);
//        bool result = false;
//        DragQ12("##x", v.x, v_speed, v_min, v_max, format, flags); SameLine();
//        DragQ12("##y", v.y, v_speed, v_min, v_max, format, flags); SameLine();
//        DragQ12("##z", v.z, v_speed, v_min, v_max, format, flags); TextUnformatted(label);
//        ImGui::PopID();
//        return result;
        auto value = dk2::Q12_decode(v);
        if(DragFloat3(label, (float *) &value, v_speed, v_min, v_max, format, flags)) {
            v = dk2::Q12_encode(value);
            return true;
        }
        return false;
    }
    bool DragAABB(const char* label, dk2::AABB &v, float v_speed = 1.0f, int v_min = 0, int v_max = 0, const char* format = "%d", ImGuiSliderFlags flags = 0) {
        return ImGui::DragInt4(label, (int *) &v, v_speed, v_min, v_max, format, flags);
    }
    bool DragI16I16(const char* label, uint32_t &v, float v_speed = 1.0f, int v_min = 0, int v_max = 0, const char* format = "%d", ImGuiSliderFlags flags = 0) {
        int value[2] { (int) (v & 0xFFFF), (int) ((v >> 16) & 0xFFFF) };
        if(ImGui::DragInt2(label, value, v_speed, v_min, v_max, format, flags)) {
            v = ((uint32_t) value[0]) | ((uint32_t) value[1] << 16);
            return true;
        }
        return false;
    }
    bool Toggle(const char* label, bool &v) {
        if(ImGui::RadioButton(label, v)) {
            v = !v;
            return true;
        }
        return false;
    }
}

namespace patch::opengl_patch {

}
namespace dk2 {


}


void patch::opengl_patch::imgui_tick() {
    static bool show_demo_window = false;
    static bool show_another_window = false;

    // 1. Show the big demo window (Most of the sample code is in ImGui::ShowDemoWindow()! You can browse its code to learn more about Dear ImGui!).
    if (show_demo_window)
        ImGui::ShowDemoWindow(&show_demo_window);

    // 2. Show a simple window that we create ourselves. We use a Begin/End pair to create a named window.
    {
        dk2::CCamera &cam = dk2::CBridge_instance.camera;

        ImGui::SetNextWindowPos(ImVec2(750, 0), ImGuiCond_FirstUseEver);
        ImGui::SetNextWindowSize(ImVec2(400, 800), ImGuiCond_FirstUseEver);
        ImGui::Begin("Visual debug");
        visual_values_render_imgui();

        ImGui::Text("manual");
        ImGui::DragFloat3("ogl cam.pos", &g_oglCtx.cam.x, 0.01f);
        ImGui::DragFloat2("ogl cam.rot", &g_oglCtx.cam.yaw, 0.01f);
        ImGui::DragFloat("g_farPlane", &dk2::g_farPlane, 0.01f);
        ImGui::DragFloat("g_2divFarPlane", &dk2::g_2divFarPlane, 0.01f);

        dk2::Pos2i &pos = dk2::CFrontEndComponent_instance.cgui_manager.mousePos;
        ImGui::InputInt2("cgui_manager.mousePos", (int *) &pos);
        ImGui::InputInt2("dk2::g_primarySurf", (int *) &dk2::g_primarySurf.surf.size);
        ImGui::InputInt2("dk2::g_offScreen", (int *) &dk2::g_offScreen.surf.size);
        ImGui::InputInt2("offScreenSurf", (int *) &dk2::MyWindow_instance.c_window_test.offScreenSurf.surf.size);

        ImGui::Toggle("dont scale XY", patch::opengl_patch::ignoreCameraMatrix[0]);
        ImGui::Toggle("m0 ignore (g_RenderData_matViewProj * *vec) + g_viewTransformTranslation", patch::opengl_patch::ignoreCameraMatrix[1]);
        ImGui::Toggle("m1 ignore (g_RenderData_matViewProj * *vec) + g_viewTransformTranslation", patch::opengl_patch::ignoreCameraMatrix[2]);
        ImGui::Toggle("m1 ignore 0x200 g_depthTriMul, g_depthTriAdd", patch::opengl_patch::ignoreCameraMatrix[3]);
        ImGui::Toggle("dont ZCapped", patch::opengl_patch::ignoreCameraMatrix[4]);
        ImGui::Toggle("identity g_baseViewProj", patch::opengl_patch::ignoreCameraMatrix[5]);
        ImGui::Toggle("computeProj ignore g_baseViewProj * (-g_cachedCameraState.v3f)", patch::opengl_patch::ignoreCameraMatrix[6]);

        ImGui::Text("editable");
        ImGui::DragQ12("cam.fovD8E", cam.fovD8E, 0.1);
        ImGui::InputInt("cam._mode", (int *) &cam._mode, 1, 2);
        ImGui::DragInt4("cam.aabbE62_clipSpace", (int *) &cam.aabbE62_clipSpace);
        ImGui::DragMat3x3f("cam.matrix", cam.matrix, 0.01f);
        ImGui::DragVec3q12("cam.location", cam.location, 0.01f);
        ImGui::DragQ12("cam.curZoomLevel", cam.curZoomLevel, 0.1);
        ImGui::DragI16I16("cam.direction", *(uint32_t *) &cam.direction, 0.01f);

        ImGui::Text("editable");
        ImGui::DragInt2("MyWindow.size", (int *) &dk2::MyWindow_instance.dwWidth);

        ImGui::Text("ignored");
        ImGui::DragInt("cam.f0", (int *) &cam.f0);
        ImGui::DragInt("cam._zoomLevel", (int *) &cam._zoomLevel);
        ImGui::DragAABB("cam.fE52", cam.fE52);
        ImGui::DragAABB("cam.fE72", cam.fE72);

        ImGui::Text("readonly");
        ImGui::DragInt("g_cgui_manager_width", &dk2::g_cgui_manager_width_6CE590);
        ImGui::DragInt("g_cgui_manager_height", &dk2::g_cgui_manager_height_6CD190);
        ImGui::DragMat3x3f("g_activeCameraState", dk2::g_activeCameraState.viewMat, 0.01f);
        ImGui::DragMat3x3f("g_cachedCameraState", dk2::g_cachedCameraState.viewMat, 0.01f);

        ImGui::DragVec3q12("cam.locationOffset", cam.locationOffset, 0.01f);

        ImGui::Text("readonly");
        ImGui::DragFloat("g_viewZMin", &dk2::g_viewZMin, 0.01f);
        ImGui::DragFloat("g_viewZMax", &dk2::g_viewZMax, 0.01f);
        ImGui::Text("readonly");
        ImGui::DragFloat2("g_depthTriMulArr", dk2::g_depthTriMulArr, 0.01f);
        ImGui::DragFloat2("g_depthTriAddArr", dk2::g_depthTriAddArr, 0.01f);
        ImGui::DragFloat2("g_depthLinearMulArr", dk2::g_depthLinearMulArr, 0.01f);
        ImGui::DragFloat2("g_depthLinearAddArr", dk2::g_depthLinearAddArr, 0.01f);
        ImGui::DragFloat2("g_depthPerspMulArr", dk2::g_depthPerspMulArr, 0.01f);
        ImGui::DragFloat2("g_depthPerspAddArr", dk2::g_depthPerspAddArr, 0.01f);
        ImGui::NewLine();
        ImGui::DragMat3x3f("g_RenderData_matViewProj", dk2::g_RenderData_matViewProj, 0.01f);

        ImGuiIO& io = ImGui::GetIO();
        ImGui::Text("Application average %.3f ms/frame (%.1f FPS)", 1000.0f / io.Framerate, io.Framerate);

        ImGui::Text("This is some useful text.");
        ImGui::Checkbox("Demo Window", &show_demo_window);
        ImGui::Checkbox("Another Window", &show_another_window);

        ImGui::End();
    }

    // 3. Show another simple window.
    if (show_another_window)
    {
        ImGui::Begin("Another Window", &show_another_window);   // Pass a pointer to our bool variable (the window will have a closing button that will clear the bool when clicked)
        ImGui::Text("Hello from another window!");
        if (ImGui::Button("Close Me"))
            show_another_window = false;
        ImGui::End();
    }
}

