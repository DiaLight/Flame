//
// Created for shader program management.
//

#ifndef BUMP_SHADERPROGRAM_H
#define BUMP_SHADERPROGRAM_H

#include <Windows.h>
#define GL_GLEXT_PROTOTYPES 1
#include <GL/gl.h>
#include <GL/glext.h>
#include <string>
#include <vector>
#include "opengl_internal.h"
#include "glm/vec2.hpp"
#include "glm/vec3.hpp"
#include "glm/vec4.hpp"
#include "glm/gtc/type_ptr.hpp"

class ShaderProgram {
public:
    ShaderProgram();
    ~ShaderProgram();

    // Load and compile vertex and fragment shaders from string sources
    bool loadFromStrings(const std::string& vertexSrc, const std::string& fragmentSrc);

    // Use this program
    void use();

    // Get uniform location
    GLint getUniformLocation(const std::string& name) const;

    // Get attribute location
    GLint getAttribLocation(const std::string& name) const;

    // Set uniform sampler
    void setUniformSampler(const std::string& name, GLuint textureUnit);

    // Enable and set attribute
    void enableAttribute(const std::string& name, int size, const void* data, GLsizei stride = 0);
    void disableAttribute();

    // Bind attribute by location
    void enableAttributeByLocation(GLuint location, int size, const void* data, GLsizei stride = 0);


    // utility uniform functions
    void setBool(const std::string &name, bool value) const {
        GLint loc = getUniformLocation(name);
        if (loc >= 0) {
            g_oglCtx.glUniform1i(loc, (int) value);
        }
    }
    void setInt(const std::string &name, int value) const {
        GLint loc = getUniformLocation(name);
        if (loc >= 0) {
            g_oglCtx.glUniform1i(loc, value);
        } else printf("loc not found %s, %d\n", name.c_str(), glGetError());
    }
    void setFloat(const std::string &name, float value) const {
        GLint loc = getUniformLocation(name);
        if (loc >= 0) {
            g_oglCtx.glUniform1f(loc, value);
        }
    }
    void setVec2(const std::string &name, const glm::vec2 &value) const {
        GLint loc = getUniformLocation(name);
        if (loc >= 0) {
            g_oglCtx.glUniform2fv(loc, 1, &value[0]);
        }
    }
    void setVec2(const std::string &name, float x, float y) const {
        GLint loc = getUniformLocation(name);
        if (loc >= 0) {
            g_oglCtx.glUniform2f(loc, x, y);
        }
    }
    void setVec3(const std::string &name, const glm::vec3 &value) const {
        GLint loc = getUniformLocation(name);
        if (loc >= 0) {
            g_oglCtx.glUniform3fv(loc, 1, glm::value_ptr(value));
        } else printf("loc not found %s, %d\n", name.c_str(), glGetError());
    }
    void setVec3(const std::string &name, float x, float y, float z) const {
        GLint loc = getUniformLocation(name);
        if (loc >= 0) {
            g_oglCtx.glUniform3f(loc, x, y, z);
        } else printf("loc not found %s, %d\n", name.c_str(), glGetError());
    }
    void setVec4(const std::string &name, const glm::vec4 &value) const {
        GLint loc = getUniformLocation(name);
        if (loc >= 0) {
            g_oglCtx.glUniform4fv(loc, 1, glm::value_ptr(value));
        }
    }
    void setVec4(const std::string &name, float x, float y, float z, float w) {
        GLint loc = getUniformLocation(name);
        if (loc >= 0) {
            g_oglCtx.glUniform4f(loc, x, y, z, w);
        }
    }
    void setMat2(const std::string &name, const glm::mat2 &mat) const {
        GLint loc = getUniformLocation(name);
        if (loc >= 0) {
            g_oglCtx.glUniformMatrix2fv(loc, 1, GL_FALSE, glm::value_ptr(mat));
        }
    }
    void setMat3(const std::string &name, const glm::mat3 &mat) const {
        GLint loc = getUniformLocation(name);
        if (loc >= 0) {
            g_oglCtx.glUniformMatrix3fv(loc, 1, GL_FALSE, glm::value_ptr(mat));
        }
    }
    void setMat4(const std::string &name, const glm::mat4 &mat) const {
        GLint loc = getUniformLocation(name);
        if (loc >= 0) {
            g_oglCtx.glUniformMatrix4fv(loc, 1, GL_FALSE, glm::value_ptr(mat));
        } else printf("loc not found %s, %d\n", name.c_str(), glGetError());
    }

private:
    GLuint program_ = 0;

    bool compileShader(GLuint shader, GLenum type, const std::string& source);
    bool linkProgram();
    void logShaderInfo(GLuint shader) const;
    void logProgramInfo() const;
};

#endif //BUMP_SHADERPROGRAM_H