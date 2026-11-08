#version 330 core

varying vec2 v_texCoords;
varying vec2 v_heightCoords;
varying vec2 v_backgroundCoords;

uniform sampler2D u_texture;
uniform sampler2D u_heightMap;
uniform sampler2D u_background;
uniform float u_bumpScale;


vec2 sampleWaterGaussian(sampler2D tex, vec2 uv, int radius) {
    vec2 texSize = textureSize(tex, 0).xy;
    vec2 blurred = vec2(0.0);
    int totalWeight = 0;

    for (int x = -radius; x <= radius; x++) {
        for (int y = -radius; y <= radius; y++) {
            vec2 offset = vec2(float(x), float(y)) / texSize;
            blurred += texture(tex, uv + offset).gb;
            totalWeight += 1;
        }
    }
    return max(blurred, vec2(0.001)) / float(totalWeight);
}


void main() {
    // Sample height map at neighboring points for finite difference
    vec2 shiftUV = sampleWaterGaussian(u_heightMap, v_heightCoords, 2);

    vec2 normShiftUv = normalize(shiftUV) * u_bumpScale;

    // Sample color texture
    vec4 color = texture(u_background, v_backgroundCoords + normShiftUv);

    // Simple diffuse lighting from height normal
    vec3 lightDir = normalize(vec3(0.5, 0.5, 1.0));
    
    // Calculate diffuse factor using dot product (Lambert's law)
    float diff = max(dot(normalize(vec3(shiftUV, 0.3)), lightDir), 0);
    
    // Apply diffuse lighting to create bump effect
    vec3 ambient = vec3(0.1);
    vec3 diffuse = vec3(1.7) * diff;
    vec3 lighting = ambient + diffuse;

    vec3 finalColor = mix(color.rgb * lighting, texture(u_texture, v_texCoords).rgb, 0.5);
    //vec3 finalColor = color.rgb;
    //vec3 finalColor = vec3(shiftUV, 0);
    //vec3 finalColor = sampleGaussian(u_heightMap, v_heightCoords, 2).rgb;

    gl_FragColor = vec4(finalColor, color.a);
}
