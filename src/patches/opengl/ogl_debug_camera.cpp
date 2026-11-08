//
// Created by DiaLight on 8/4/2026.
//

#include "ogl_debug_camera.h"
#include "opengl_internal.h"
#include "dk2_globals.h"
#include "tools/png_support.h"
#include "tools/visual_debug.h"
#include <exception>
#include "glm/glm.hpp"
#include "glm/gtc/matrix_transform.hpp"
#include "glm/gtc/type_ptr.hpp"
#include "dk2/engine/game_engine.h"


// ==================== Camera State ====================

// Camera position and orientation

// Camera movement speed (units per second)
const float CAMERA_MOVE_SPEED = 0.4f;

// Camera rotation speed for Q/E keys (degrees per second)
const float CAMERA_ROTATE_SPEED = 120.0f;

// Keyboard state
static bool g_keys[256] = {false};

// Math constants
static const float PI = 3.14159265358979323846f;


// Save current OpenGL matrices
void patch::opengl_patch::SaveMatrices(GLfloat* projOut, GLfloat* modelviewOut) {
    glMatrixMode(GL_PROJECTION);
    glGetFloatv(GL_PROJECTION_MATRIX, projOut);
    glMatrixMode(GL_MODELVIEW);
    glGetFloatv(GL_MODELVIEW_MATRIX, modelviewOut);
}

// Restore OpenGL matrices
void patch::opengl_patch::RestoreMatrices(const GLfloat* proj, const GLfloat* modelview) {
    glMatrixMode(GL_PROJECTION);
    glLoadMatrixf(proj);
    glMatrixMode(GL_MODELVIEW);
    glLoadMatrixf(modelview);
}

// Setup orthographic projection for 2D rendering
void patch::opengl_patch::Setup2DProjection(int width, int height) {
    glMatrixMode(GL_PROJECTION);
    glLoadIdentity();

//    float original_aspect = 640.f / 480.f;
//    float window_aspect = (float) width / height;
//    float adjusted_aspect = window_aspect / original_aspect;
//    if(window_aspect > original_aspect) {
//        glOrtho(
//                -adjusted_aspect, adjusted_aspect, -1, 1,
//                -1.0, 1.0
//        );
//    } else {
//        glOrtho(
//                -1, 1, -1.f / adjusted_aspect, 1.f / adjusted_aspect,
//                -1.0, 1.0
//        );
//    }

    glOrtho(-1, 1, -1, 1, -1.0, 1.0);

    glMatrixMode(GL_MODELVIEW);
    glLoadIdentity();
}


// ==================== Camera Functions ====================

void UpdateCamera(DWORD elapsed) {
    float elapsedSec = elapsed / 1000.0f;
    float moveAmount = CAMERA_MOVE_SPEED * elapsedSec;
    float rotateAmount = CAMERA_ROTATE_SPEED * elapsedSec;

    // Calculate forward and right vectors from yaw
    float yawRad = g_oglCtx.cam.yaw * PI / 180.0f;
    float forwardX = -sinf(yawRad);
    float forwardZ = -cosf(yawRad);
    float rightX = cosf(yawRad);
    float rightZ = -sinf(yawRad);

    // WASD movement
    if (g_keys['W']) {
        g_oglCtx.cam.x += forwardX * moveAmount;
        g_oglCtx.cam.z += forwardZ * moveAmount;
    }
    if (g_keys['S']) {
        g_oglCtx.cam.x -= forwardX * moveAmount;
        g_oglCtx.cam.z -= forwardZ * moveAmount;
    }
    if (g_keys['A']) {
        g_oglCtx.cam.x -= rightX * moveAmount;
        g_oglCtx.cam.z -= rightZ * moveAmount;
    }
    if (g_keys['D']) {
        g_oglCtx.cam.x += rightX * moveAmount;
        g_oglCtx.cam.z += rightZ * moveAmount;
    }
    // Q = yaw left (counter-clockwise), E = yaw right (clockwise)
    if (g_keys['Q']) {
        g_oglCtx.cam.yaw += rotateAmount;
    }
    if (g_keys['E']) {
        g_oglCtx.cam.yaw -= rotateAmount;
    }
    // Space = up, Shift = down
    if (g_keys[' ']) {
        g_oglCtx.cam.y += moveAmount;
    }
    if (g_keys[VK_SHIFT]) {
        g_oglCtx.cam.y -= moveAmount;
    }
}

glm::mat4 patch::opengl_patch::GetViewMatrix() {
    // Convert camera angles to radians
    float yawRad = g_oglCtx.cam.yaw * PI / 180.0f;
    float pitchRad = g_oglCtx.cam.pitch * PI / 180.0f;

    // Build view matrix using GLM matrix multiplication
    // View matrix = Translation(-cameraPosition) * RotationY(-yaw) * RotationX(-pitch)
    // GLM uses column-major, but OpenGL expects column-major by default

    // Create rotation matrices (negative for view direction)
    glm::mat4 rotY = glm::rotate(glm::mat4(1.0f), -yawRad, glm::vec3(0.0f, 1.0f, 0.0f));
    glm::mat4 rotX = glm::rotate(glm::mat4(1.0f), -pitchRad, glm::vec3(1.0f, 0.0f, 0.0f));

    // Create translation matrix (negative camera position)
    glm::mat4 trans = glm::translate(glm::mat4(1.0f), glm::vec3(-g_oglCtx.cam.x, -g_oglCtx.cam.y, -g_oglCtx.cam.z));

    glm::mat4 viewMatrix = rotY * rotX * trans;
//    float zoomFactor = 1.f / 100.f;
//    viewMatrix = glm::scale(viewMatrix, glm::vec3(zoomFactor, -zoomFactor, 1.0f));
    return viewMatrix;
}

void patch::opengl_patch::TickOglCamera() {
    g_keys['W'] = ( 1 << 15 ) & GetAsyncKeyState(VK_NUMPAD8);
    g_keys['A'] = ( 1 << 15 ) & GetAsyncKeyState(VK_NUMPAD4);
    g_keys['S'] = ( 1 << 15 ) & GetAsyncKeyState(VK_NUMPAD5);
    g_keys['D'] = ( 1 << 15 ) & GetAsyncKeyState(VK_NUMPAD6);
    g_keys['Q'] = ( 1 << 15 ) & GetAsyncKeyState(VK_NUMPAD7);
    g_keys['E'] = ( 1 << 15 ) & GetAsyncKeyState(VK_NUMPAD9);
    g_keys[' '] = ( 1 << 15 ) & GetAsyncKeyState(' ');
    g_keys[VK_SHIFT] = ( 1 << 15 ) & GetAsyncKeyState(VK_SHIFT);

    UpdateCamera(30);
}

