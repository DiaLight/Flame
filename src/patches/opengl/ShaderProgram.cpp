//
// Created for shader program management.
//

#include "ShaderProgram.h"
#include "opengl_internal.h"
#include <iostream>

ShaderProgram::ShaderProgram() {}

ShaderProgram::~ShaderProgram() {
    if (program_) {
        g_oglCtx.glDeleteProgram(program_);
    }
}

bool ShaderProgram::compileShader(GLuint shader, GLenum type, const std::string& source) {
    const char* src = source.c_str();
    g_oglCtx.glShaderSource(shader, 1, &src, nullptr);
    g_oglCtx.glCompileShader(shader);

    // Check compile status
    GLint success = GL_FALSE;
    g_oglCtx.glGetShaderiv(shader, GL_COMPILE_STATUS, &success);
    if (!success) {
        GLchar infoLog[1024];
        g_oglCtx.glGetShaderInfoLog(shader, 1024, nullptr, infoLog);
        std::cerr << "Shader compilation failed (" << (type == GL_VERTEX_SHADER ? "vertex" : "fragment") << "):\n" << infoLog << std::endl;
        return false;
    }
    return true;
}

bool ShaderProgram::linkProgram() {
    g_oglCtx.glLinkProgram(program_);

    GLint success = GL_FALSE;
    g_oglCtx.glGetProgramiv(program_, GL_LINK_STATUS, &success);
    if (!success) {
        GLchar infoLog[1024];
        g_oglCtx.glGetProgramInfoLog(program_, 1024, nullptr, infoLog);
        std::cerr << "Program linking failed:\n" << infoLog << std::endl;
        return false;
    }
    return true;
}

bool ShaderProgram::loadFromStrings(const std::string& vertexSrc, const std::string& fragmentSrc) {
    // Create program
    program_ = g_oglCtx.glCreateProgram();
    if (!program_) {
        std::cerr << "Failed to create shader program" << std::endl;
        return false;
    }

    // Create and compile vertex shader
    GLuint vs = g_oglCtx.glCreateShader(GL_VERTEX_SHADER);
    if (!compileShader(vs, GL_VERTEX_SHADER, vertexSrc)) {
        g_oglCtx.glDeleteShader(vs);
        return false;
    }
    g_oglCtx.glAttachShader(program_, vs);
    g_oglCtx.glDeleteShader(vs);

    // Create and compile fragment shader
    GLuint fs = g_oglCtx.glCreateShader(GL_FRAGMENT_SHADER);
    if (!compileShader(fs, GL_FRAGMENT_SHADER, fragmentSrc)) {
        g_oglCtx.glDeleteShader(fs);
        return false;
    }
    g_oglCtx.glAttachShader(program_, fs);
    g_oglCtx.glDeleteShader(fs);

    // Link program
    if (!linkProgram()) {
        g_oglCtx.glDeleteProgram(program_);
        program_ = 0;
        return false;
    }

    std::cout << "Shader program linked successfully" << std::endl;
    return true;
}

void ShaderProgram::use() {
    g_oglCtx.glUseProgram(program_);
}

GLint ShaderProgram::getUniformLocation(const std::string& name) const {
    return g_oglCtx.glGetUniformLocation(program_, name.c_str());
}

GLint ShaderProgram::getAttribLocation(const std::string& name) const {
    return g_oglCtx.glGetAttribLocation(program_, name.c_str());
}

void ShaderProgram::setUniformSampler(const std::string& name, GLuint textureUnit) {
    GLint loc = g_oglCtx.glGetUniformLocation(program_, name.c_str());
    if (loc >= 0) {
        g_oglCtx.glActiveTexture(GL_TEXTURE0 + textureUnit);
        g_oglCtx.glUniform1i(loc, static_cast<GLint>(textureUnit));
    }
}

void ShaderProgram::enableAttribute(const std::string& name, int size, const void* data, GLsizei stride) {
    GLint loc = g_oglCtx.glGetAttribLocation(program_, name.c_str());
    if (loc >= 0) {
        g_oglCtx.glEnableVertexAttribArray(static_cast<GLuint>(loc));
        g_oglCtx.glVertexAttribPointer(static_cast<GLuint>(loc), size, GL_FLOAT, GL_FALSE, stride, data);
    }
}

void ShaderProgram::disableAttribute() {
    // Disable all vertex attribute arrays (0-15)
    for (GLint i = 0; i < 16; ++i) {
        g_oglCtx.glDisableVertexAttribArray(static_cast<GLuint>(i));
    }
}

void ShaderProgram::enableAttributeByLocation(GLuint location, int size, const void* data, GLsizei stride) {
    g_oglCtx.glEnableVertexAttribArray(location);
    g_oglCtx.glVertexAttribPointer(location, size, GL_FLOAT, GL_FALSE, stride, data);
}
