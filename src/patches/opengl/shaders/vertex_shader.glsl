#version 330 core

layout (location = 0) in vec3 a_position;
layout (location = 1) in vec2 a_texCoords;
layout (location = 2) in vec2 a_heightCoords;
layout (location = 3) in vec2 a_backgroundCoords;

uniform mat4 u_mvp;

varying vec2 v_texCoords;
varying vec2 v_heightCoords;
varying vec2 v_backgroundCoords;

void main() {
    v_texCoords = a_texCoords;
    v_heightCoords = a_heightCoords;
    v_backgroundCoords = a_backgroundCoords;
    gl_Position = u_mvp * vec4(a_position, 1.0);
}
