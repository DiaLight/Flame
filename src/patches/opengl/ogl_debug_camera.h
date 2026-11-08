//
// Created by DiaLight on 8/4/2026.
//

#ifndef FLAME_OGL_DEBUG_CAMERA_H
#define FLAME_OGL_DEBUG_CAMERA_H

#include "glm/ext/matrix_float4x4.hpp"

typedef float GLfloat;

namespace patch::opengl_patch {

    void TickOglCamera();
    glm::mat4 GetViewMatrix();
    void Setup2DProjection(int width, int height);

    void SaveMatrices(GLfloat* projOut, GLfloat* modelviewOut);
    void RestoreMatrices(const GLfloat* proj, const GLfloat* modelview);

}


#endif //FLAME_OGL_DEBUG_CAMERA_H
