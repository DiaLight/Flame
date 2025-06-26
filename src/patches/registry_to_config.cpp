//
// Created by DiaLight on 4/11/2025.
//

#include "registry_to_config.h"

#include <map>
#include <set>
#include <sstream>
#include <string>
#include <vector>
#include <tools/flame_config.h>
#include <iomanip>
#include <tools/bug_hunter.h>

#define fmtHex8(val) std::hex << std::setw(2) << std::setfill('0') << std::uppercase << ((DWORD) val) << std::dec

using namespace patch::registry_to_config;

void scanfGuid(const char *str, GUID *a4_guid);

bool patch::registry_to_config::enabled = true;

namespace patch::registry_to_config {

    std::map<std::string, std::vector<uint8_t>> gdata;

    struct Reg2Cfg {
        virtual ~Reg2Cfg() = default;
        std::string path;
        std::string name;
        bool builtin;
        explicit Reg2Cfg(const std::string &path, const std::string &name, bool builtin = false) : path(path + ':' + name), name(name), builtin(builtin) {}

        virtual bool writeBytes(const std::string &field, const void *data, size_t size) { return false; }
        virtual size_t readBytesSize(const std::string &field) { return 0; }
        virtual bool readBytes(const std::string &field, void *data, size_t size) { return false; }

        virtual bool writeInt(const std::string &field, int value) {
            return writeBytes(field, &value, sizeof(value));
        }
        virtual bool readInt(const std::string &field, int &value) {
            return readBytes(field, &value, sizeof(value));
        }

        virtual bool writeGuid(const std::string &field, const GUID *value) {
            return writeBytes(field, value, sizeof(GUID));
        }
        virtual bool readGuid(const std::string &field, GUID *value) {
            return readBytes(field, value, sizeof(GUID));
        }

        virtual bool writeString(const std::string &field, const char *value) {
            return writeBytes(field, value, strlen(value));
        }
        virtual bool readString(const std::string &field, char *buf, size_t bufSize) {
            return readBytes(field, buf, bufSize);
        }
    };

}


namespace registry {

    int prsHex4(char val) {
        if (val >= '0' && val <= '9') return (val - '0');
        if (val >= 'A' && val <= 'F') return (val - 'A') + 10;
        if (val >= 'a' && val <= 'f') return (val - 'a') + 10;
        return -1;
    }

    struct define_reg_option {
        virtual ~define_reg_option() = default;

        std::string name;
        explicit define_reg_option(const char *name) : name(name) {}

        virtual size_t size() { return 0; }
        virtual bool read(void *data, size_t size) { return false; }
        virtual bool write(const void *data, size_t size) { return false; }

    };
    struct define_reg_int_option : define_reg_option {
        flame_config::define_flame_option<int> opt;

        define_reg_int_option(const char *name, const char *path, const char *help, int defaultValue) : define_reg_option(name), opt(path, help, defaultValue) {}

        size_t size() override { return 4; }
        bool read(void *data, size_t size) override {
            if (size != 0 && size != 4) return false;
            *(int *) data = opt.get();
            return true;
        }
        bool write(const void *data, size_t size) override {
            if (size != 4) return false;
            opt.set(*(int *) data);
            return true;
        }

    };
    struct define_reg_bool_option : define_reg_option {
        flame_config::define_flame_option<bool> opt;

        define_reg_bool_option(const char *name, const char *path, const char *help, bool defaultValue) : define_reg_option(name), opt(path, help, defaultValue) {}

        size_t size() override { return 4; }
        bool read(void *data, size_t size) override {
            if (size != 0 && size != 4) return false;
            *(int *) data = opt.get() ? 1 : 0;
            return true;
        }
        bool write(const void *data, size_t size) override {
            if (size != 4) return false;
            int value = *(int *) data;
            if (value != 0 && value != 1) return false;
            opt.set(value != 0);
            return true;
        }

    };
    struct define_reg_bytes_option : define_reg_option {
        size_t sz;
        flame_config::define_flame_option<std::string> opt;

        define_reg_bytes_option(const char *name, size_t size, const char *path, const char *help, std::string defaultValue) : define_reg_option(name), sz(size), opt(path, help, defaultValue) {}

        size_t size() override { return sz; }
        bool read(void *data, size_t size) override {
            std::string value = *opt;
            if (value.empty()) return false;
            auto *bytes = (uint8_t *) data;
            size_t valueSz = value.size() / 2;
            size_t expectSize = sz;
            if (size != 0 && expectSize > size) expectSize = size;
            if (size != 0 && valueSz > size) valueSz = size;
            const char *valueS = value.c_str();
            int i = 0;
            for (; i < valueSz; ++i) {
                int high = prsHex4(valueS[i * 2 + 0]);
                int low = prsHex4(valueS[i * 2 + 1]);
                if (high == -1 || low == -1) return false;
                bytes[i] = high << 4 | low;
            }
            for (; i < expectSize; ++i) {
                bytes[i] = 0x00;
            }
            return true;
        }
        bool write(const void *data, size_t size) override {
            auto *bytes = (const uint8_t *) data;
            std::stringstream ss;
            for (int i = 0; i < size; ++i) {
                ss << fmtHex8(bytes[i]);
            }
            std::string value = ss.str();
            opt.set(value);
            return true;
        }

    };
    struct define_reg_string_option : define_reg_option {
        flame_config::define_flame_option<std::string> opt;

        define_reg_string_option(const char *name, const char *path, const char *help, std::string defaultValue) : define_reg_option(name), opt(path, help, defaultValue) {}

        size_t size() override { return opt->size(); }
        bool read(void *data, size_t size) override {
            std::string value = *opt;
            if (value.empty()) return false;
            strncpy((char *) data, value.c_str(), size);
            return true;
        }
        bool write(const void *data, size_t size) override {
            std::string value((const char *) data, size);
            opt.set(value);
            return true;
        }

    };
    struct define_reg_guid_option : define_reg_option {
        flame_config::define_flame_option<std::string> opt;

        define_reg_guid_option(const char *name, const char *path, const char *help, std::string defaultValue) : define_reg_option(name), opt(path, help, defaultValue) {}

        size_t size() override { return sizeof(GUID); }
        bool read(void *data, size_t size) override {
            if (size != sizeof(GUID)) return false;
            std::string value = *opt;
            if (value.empty()) return false;
            scanfGuid(value.c_str(), (GUID *) data);
            return true;
        }
        bool write(const void *data, size_t size) override {
            if (size != sizeof(GUID)) return false;
            auto *guid = (GUID *) data;
            char value[40];
            sprintf(
              value,
              "{%.8X-%.4X-%.4X-%.2X%.2X-%.2X%.2X%.2X%.2X%.2X%.2X}",
              guid->Data1,
              guid->Data2,
              guid->Data3,
              guid->Data4[0],
              guid->Data4[1],
              guid->Data4[2],
              guid->Data4[3],
              guid->Data4[4],
              guid->Data4[5],
              guid->Data4[6],
              guid->Data4[7]);
            std::string s(value);
            opt.set(s);
            return true;
        }

    };

    struct Reg2CfgOptions final : Reg2Cfg {
        define_reg_option **options;
        size_t count;
        explicit Reg2CfgOptions(const std::string &path, const std::string &name, define_reg_option **options, size_t count)
            : Reg2Cfg(path, name, true), options(options), count(count) {}

        bool writeBytes(const std::string &field, const void *data, size_t size) override {
            for (int i = 0; i < count; ++i) {
                if (field == options[i]->name) return options[i]->write(data, size);
            }
            return false;
        }
        size_t readBytesSize(const std::string &field) override {
            for (int i = 0; i < count; ++i) {
                if (field == options[i]->name) return options[i]->size();
            }
            return 0;
        }
        bool readBytes(const std::string &field, void *data, size_t size) override {
            for (int i = 0; i < count; ++i) {
                if (field == options[i]->name) return options[i]->read(data, size);
            }
            return false;
        }

    };

}

namespace registry::dk2::configuration::paths {

    define_reg_int_option o_version(
        "Version Number",
        "registry:configuration:paths:Version_Number",
        "DKII registry paths config version\n",
        0
    );

    define_reg_option *options[] {
        &o_version,
    };

    Reg2CfgOptions r2c("dk2:Cfg", "Paths", options, ARRAYSIZE(options));

}

namespace registry::dk2::configuration::video {
    // 00563FB0 MyVideoSettings_writeDefaultValues

    define_reg_int_option o_version(
        "Version Number",
        "registry:configuration:video:Version_Number",
        "DKII registry video config version\n",
        4
    );

    define_reg_int_option o_guidIndex(
        "GUID Index",
        "registry:configuration:video:GUID_Index",
        "",
        0
    );

    define_reg_bool_option o_guidIndexVerifiedWorking(
        "GUID Index Verified Working",
        "registry:configuration:video:GUID_Index_Verified_Working",
        "",
        false
    );

    define_reg_bool_option o_guidIndexIsDefault(
        "GUID Index Is Default",
        "registry:configuration:video:GUID_Index_Is_Default",
        "",
        true
    );

    define_reg_int_option o_gammaLevel(
        "Gamma Level",
        "registry:configuration:video:Gamma_Level",
        "",
        4096
    );

    define_reg_int_option o_ambientLight(
        "Ambient Light",
        "registry:configuration:video:Ambient_Light",
        "",
        512
    );

    define_reg_bool_option o_highWalls(
        "HighWalls",
        "registry:configuration:video:HighWalls",
        "",
        true
    );

    define_reg_bool_option o_tortureDetails(
        "Torture Details",
        "registry:configuration:video:Torture_Details",
        "if file Data\\TFile.tld exists, then dk2 will set value to false for some reason",
        true
    );

    define_reg_bool_option o_res1024_768Enabled(
        "Res 1024*768 Enabled",
        "registry:configuration:video:Res_1024_768_Enabled",
        "dk2 default value is false but I will set it to true",
        true
    );

    define_reg_bool_option o_res1280_1024Enable(
        "Res 1280*1024 Enable",
        "registry:configuration:video:Res_1280_1024_Enable",
        "",
        false
    );

    define_reg_bool_option o_res1600_1200Enable(
        "Res 1600*1200 Enable",
        "registry:configuration:video:Res_1600_1200_Enable",
        "",
        false
    );

    define_reg_int_option o_engineId(
        "Engine Id",
        "registry:configuration:video:Engine_Id",
        "if video device support linear perspective then value eq 2 else 4",
        2
    );

    define_reg_bool_option o_cheapLighting(
        "Cheap Lighting",
        "registry:configuration:video:Cheap_Lighting",
        "",
        false
    );

    define_reg_bool_option o_sineWaveWater(
        "Sine Wave Water",
        "registry:configuration:video:Sine_Wave_Water",
        "",
        false
    );

    define_reg_int_option o_viewDistance(
        "View Distance",
        "registry:configuration:video:View_Distance",
        "",
        12
    );

    define_reg_int_option o_shadowLevel(
        "Shadow Level",
        "registry:configuration:video:Shadow_Level",
        "",
        3
    );

    define_reg_bool_option o_environmentMapping(
        "EnvironmentMapping",
        "registry:configuration:video:EnvironmentMapping",
        "",
        true
    );

    define_reg_bool_option o_translucentWater(
        "Translucent Water",
        "registry:configuration:video:Translucent_Water",
        "",
        true
    );

    define_reg_int_option o_pMeshReductionLevel(
        "PMesh Reduction Level",
        "registry:configuration:video:PMesh_Reduction_Level",
        "",
        0
    );

    define_reg_int_option o_textureReductionLevel(
        "Texture Reduction Level",
        "registry:configuration:video:Texture_Reduction_Level",
        "on slow cpu if video device support linear perspective then value 1 else 2",
        0
    );

    define_reg_bool_option o_solidBlueprints(
        "Solid Blueprints",
        "registry:configuration:video:Solid_Blueprints",
        "on slow cpu if video device support linear perspective then value true",
        false
    );

    define_reg_bool_option o_shouldDrawOptBackgroundAlpha(
        "Should Draw Opt Background Alpha",
        "registry:configuration:video:Should_Draw_Opt_Background_Alpha",
        "",
        true
    );

    define_reg_int_option o_screenWidth(
        "Screen Width",
        "registry:configuration:video:Screen_Width",
        "in game rendering width\n"
        "dk2 default value is 800 but I will set it to 1024",
        1024
    );

    define_reg_int_option o_screenHeight(
        "Screen Height",
        "registry:configuration:video:Screen_Height",
        "in game rendering height\n"
        "dk2 default value is 600 but I will set it to 768",
        768
    );

    define_reg_int_option o_screenDepth(
        "Screen Depth",
        "registry:configuration:video:Screen_Depth",
        "",
        16
    );

    define_reg_bool_option o_screenWindowed(
        "Screen Windowed",
        "registry:configuration:video:Screen_Windowed",
        "",
        false
    );

    define_reg_bool_option o_screenSwap(
        "Screen Swap",
        "registry:configuration:video:Screen_Swap",
        "",
        false
    );

    define_reg_bool_option o_screenHardware3D(
        "Screen Hardware3D",
        "registry:configuration:video:Screen_Hardware3D",
        "",
        true
    );

    define_reg_int_option o_machineSpecLevel(
        "Machine Spec Level",
        "registry:configuration:video:Machine_Spec_Level",
        "",
        10
    );

    define_reg_bool_option o_highResTextures(
        "High Res Textures",
        "registry:configuration:video:High_Res_Textures",
        "if RAM > 32mb then true",
        true
    );

    define_reg_bool_option o_bumpMappingConfig(
        "BumpMappingConfig",
        "registry:configuration:video:BumpMappingConfig",
        "write only. Registry value is ignored. Use command line flag -EnableBumpMapping",
        false
    );

    define_reg_guid_option o_guidDeviceGuid(
        "D3D Device Guid",
        "registry:configuration:video:D3D_Device_Guid",
        "last selected device",
        ""
    );

    define_reg_int_option o_screenModeType(
        "Screen Mode Type",
        "registry:configuration:video:Screen_Mode_Type",
        "keeps the last selected value\n"
        "0: 400x300\n"
        "1: 512x384\n"
        "2: 640x480 if VRAM > 2mb\n"
        "3: 800x600 if VRAM > 3mb\n"
        "4: 1024x768 if VRAM > 6mb  (most stable)\n"
        "5: 1280x1024 if VRAM > 10mb  (crashes the game)\n"
        "6: 1600x1200 if VRAM > 14mb  (fonts not loading)\n"
        "dk2 default value is calculated based on RAM size but I will set it to 4\n"
        "",
        4
    );

    define_reg_bool_option o_stippleAlpha(
        "StippleAlpha",
        "registry:configuration:video:StippleAlpha",
        "Changes the alpha blending mode when copying one texture to another",
        false
    );

    define_reg_option *options[] {
        &o_version,
        &o_guidIndex,
        &o_guidIndexVerifiedWorking,
        &o_guidIndexIsDefault,
        &o_gammaLevel,
        &o_ambientLight,
        &o_highWalls,
        &o_tortureDetails,
        &o_res1024_768Enabled,
        &o_res1280_1024Enable,
        &o_res1600_1200Enable,
        &o_engineId,
        &o_cheapLighting,
        &o_sineWaveWater,
        &o_viewDistance,
        &o_shadowLevel,
        &o_environmentMapping,
        &o_translucentWater,
        &o_pMeshReductionLevel,
        &o_textureReductionLevel,
        &o_solidBlueprints,
        &o_shouldDrawOptBackgroundAlpha,
        &o_screenWidth,
        &o_screenHeight,
        &o_screenDepth,
        &o_screenWindowed,
        &o_screenSwap,
        &o_screenHardware3D,
        &o_machineSpecLevel,
        &o_highResTextures,
        &o_bumpMappingConfig,
        &o_guidDeviceGuid,
        &o_screenModeType,
        &o_stippleAlpha,
    };

    Reg2CfgOptions r2c("dk2:Cfg", "Video", options, ARRAYSIZE(options));

}

namespace registry::dk2::configuration::player {

    define_reg_int_option o_version(
        "Version Number",
        "registry:configuration:player:Version_Number",
        "DKII registry player config version\n",
        1
    );

    define_reg_int_option o_transferCreatureID(
        "Transfer Creature ID",
        "registry:configuration:player:Transfer_Creature_ID",
        "",
        0
    );

    define_reg_int_option o_transferCreatureLevel(
        "Transfer Creature Level",
        "registry:configuration:player:Transfer_Creature_Level",
        "",
        0
    );

    define_reg_int_option o_levelNumber(
        "Level Number",
        "registry:configuration:player:Level_Number",
        "",
        1
    );

    define_reg_int_option o_mpdLevelNumber(
        "MPD Level Number",
        "registry:configuration:player:MPD_Level_Number",
        "",
        1
    );

    define_reg_bool_option o_invertMouse(
        "Invert Mouse",
        "registry:configuration:player:Invert_Mouse",
        "",
        false
    );

    define_reg_int_option o_mouseSensitivity(
        "Mouse Sensitivity",
        "registry:configuration:player:Mouse_Sensitivity",
        "",
        2
    );

    define_reg_int_option o_scrollSpeed(
        "ScrollSpeed",
        "registry:configuration:player:ScrollSpeed",
        "",
        10
    );

    define_reg_bool_option o_useBlood(
        "Use Blood",
        "registry:configuration:player:Use_Blood",
        "if file Data\\BFile.bld exists, then dk2 will set value to false for some reason",
        true
    );

    define_reg_bool_option o_messageTabsEnabled(
        "Message Tabs Enabled",
        "registry:configuration:player:Message_Tabs_Enabled",
        "",
        true
    );

    define_reg_bool_option o_worldTooltipsEnabled(
        "World Tooltips Enabled",
        "registry:configuration:player:World_Tooltips_Enabled",
        "",
        true
    );

    define_reg_bool_option o_alternativeScroll(
        "Alternative Scroll",
        "registry:configuration:player:Alternative_Scroll",
        "",
        false
    );

    define_reg_bytes_option o_keyTable(
        "Key Table", 512,
        "registry:configuration:player:Key_Table",
        "",
        ""
    );

    define_reg_bytes_option o_secretLevels(
        "Secret Levels", 64,
        "registry:configuration:player:Secret_Levels",
        "",
        ""
    );

    define_reg_bytes_option o_secretLevelsCompleted(
        "Secret Levels Completed", 64,
        "registry:configuration:player:Secret_Levels_Completed",
        "",
        ""
    );

    define_reg_bytes_option o_specialLevelsCompleted(
        "Special Levels Completed", 64,
        "registry:configuration:player:Special_Levels_Completed",
        "",
        ""
    );

    define_reg_bytes_option o_petDungeonLevelsCompleted(
        "Pet Dungeon Levels Completed", 28,
        "registry:configuration:player:Pet_Dungeon_Levels_Completed",
        "",
        ""
    );

    define_reg_int_option o_secretLevelNumber(
        "Secret Level Number",
        "registry:configuration:player:Secret_Level_Number",
        "",
        0
    );

    define_reg_string_option o_multiplayerName(
        "Multiplayer Name",
        "registry:configuration:player:Multiplayer_Name",
        "",
        ""
    );

    define_reg_bytes_option o_levelAttempts(
        "Level Attempts", 160,
        "registry:configuration:player:Level_Attempts",
        "",
        ""
    );

    define_reg_bytes_option o_playerLevelStatus(
        "Player Level Status", 160,
        "registry:configuration:player:Player_Level_Status",
        "",
        ""
    );

    define_reg_bytes_option o_totalEvilRating(
        "Total Evil Rating", 160,
        "registry:configuration:player:Total_Evil_Rating",
        "",
        ""
    );

    define_reg_bytes_option o_userCameras(
        "User Cameras", 30,
        "registry:configuration:player:User_Cameras",
        "Write only. Didn't found any read usages",
        "00"
    );

    define_reg_string_option o_multiplayerGameName(
        "Multiplayer Game Name",
        "registry:configuration:player:Multiplayer_Game_Name",
        "",
        ""
    );

    define_reg_option *options[] {
        &o_version,
        &o_transferCreatureID,
        &o_transferCreatureLevel,
        &o_levelNumber,
        &o_mpdLevelNumber,
        &o_invertMouse,
        &o_mouseSensitivity,
        &o_scrollSpeed,
        &o_useBlood,
        &o_messageTabsEnabled,
        &o_worldTooltipsEnabled,
        &o_alternativeScroll,
        &o_keyTable,
        &o_secretLevels,
        &o_secretLevelsCompleted,
        &o_specialLevelsCompleted,
        &o_petDungeonLevelsCompleted,
        &o_secretLevelNumber,
        &o_multiplayerName,
        &o_levelAttempts,
        &o_playerLevelStatus,
        &o_totalEvilRating,
        &o_userCameras,
        &o_multiplayerGameName,
    };

    Reg2CfgOptions r2c("dk2:Cfg", "Player", options, ARRAYSIZE(options));

}


namespace registry::dk2::configuration::network {

    define_reg_int_option o_version(
        "Version Number",
        "registry:configuration:network:Version_Number",
        "DKII registry network config version\n",
        0
        );

    define_reg_string_option o_serverName(
        "Server Name",
        "registry:configuration:network:Server_Name",
        "",
        "daphne.eagames.co.uk"
    );

    define_reg_option *options[] {
        &o_version,
        &o_serverName,
    };

    Reg2CfgOptions r2c("dk2:Cfg", "Network", options, ARRAYSIZE(options));

}


namespace registry::dk2::configuration::sound {

    define_reg_int_option o_version(
        "Version Number",
        "registry:configuration:sound:Version_Number",
        "DKII registry sound config version\n",
        2
    );

    define_reg_int_option o_speechVolume(
        "SpeechVolume",
        "registry:configuration:sound:SpeechVolume",
        "",
        100
    );

    define_reg_int_option o_soundEffectVolume(
        "SoundEffectVolume",
        "registry:configuration:sound:SoundEffectVolume",
        "",
        50
    );

    define_reg_int_option o_musicVolume(
        "MusicVolume",
        "registry:configuration:sound:MusicVolume",
        "",
        50
    );

    define_reg_int_option o_masterVolume(
        "MasterVolume",
        "registry:configuration:sound:MasterVolume",
        "",
        100
    );

    define_reg_int_option o_masterBalance(
        "MasterBalance",
        "registry:configuration:sound:MasterBalance",
        "Didn't found any usages. Probably unused field",
        0
    );

    define_reg_bool_option o_headphones(
        "Headphones",
        "registry:configuration:sound:Headphones",
        "",
        false
    );

    define_reg_bool_option o_flipSpeakers(
        "FlipSpeakers",
        "registry:configuration:sound:FlipSpeakers",
        "",
        false
    );

    define_reg_bool_option o_musicSwitch(
        "MusicSwitch",
        "registry:configuration:sound:MusicSwitch",
        "",
        true
    );

    define_reg_bool_option o_speechSwitch(
        "SpeechSwitch",
        "registry:configuration:sound:SpeechSwitch",
        "",
        true
    );

    define_reg_bool_option o_sfxSwtich(
        "SFXSwtich",
        "registry:configuration:sound:SFXSwtich",
        "",
        true
    );

    define_reg_int_option o_soundQuality(
        "SoundQuality",
        "registry:configuration:sound:SoundQuality",
        "",
        3
    );

    define_reg_bool_option o_qSound(
        "QSound",
        "registry:configuration:sound:QSound",
        "",
        true
    );

    define_reg_int_option o_numberOfVoices(
        "NumberOfVoices",
        "registry:configuration:sound:NumberOfVoices",
        "",
        12
    );

    define_reg_bool_option o_environmentalEffects(
        "EnvironmentalEffects",
        "registry:configuration:sound:EnvironmentalEffects",
        "",
        true
    );

    define_reg_option *options[] {
        &o_version,
        &o_speechVolume,
        &o_soundEffectVolume,
        &o_musicVolume,
        &o_masterVolume,
        &o_masterBalance,
        &o_headphones,
        &o_flipSpeakers,
        &o_musicSwitch,
        &o_speechSwitch,
        &o_sfxSwtich,
        &o_soundQuality,
        &o_qSound,
        &o_numberOfVoices,
        &o_environmentalEffects,
    };

    Reg2CfgOptions r2c("dk2:Cfg", "Sound", options, ARRAYSIZE(options));

}


namespace registry::dk2::configuration::game {

    define_reg_int_option o_version(
        "Version Number",
        "registry:configuration:game:Version_Number",
        "DKII registry game config version\n",
        0
    );

    define_reg_int_option o_gameSpeed(
        "GameSpeed",
        "registry:configuration:game:GameSpeed",
        "",
        4
    );

    define_reg_bool_option o_fogOfWar(
        "FogOfWar",
        "registry:configuration:game:FogOfWar",
        "",
        true
    );

    define_reg_bool_option o_impenetrableWalls(
        "ImpenetrableWalls",
        "registry:configuration:game:ImpenetrableWalls",
        "",
        false
    );

    define_reg_int_option o_goldDensity(
        "GoldDensity",
        "registry:configuration:game:GoldDensity",
        "",
        1
    );

    define_reg_int_option o_gameDuration(
        "GameDuration",
        "registry:configuration:game:GameDuration",
        "",
        0
    );

    define_reg_int_option o_loseHeartType(
        "LoseHeartType",
        "registry:configuration:game:LoseHeartType",
        "",
        0
    );

    define_reg_int_option o_maxCreatures(
        "MaxCreatures",
        "registry:configuration:game:MaxCreatures",
        "",
        32
    );

    define_reg_bool_option o_manaRegeneration(
        "ManaRegeneration",
        "registry:configuration:game:ManaRegeneration",
        "",
        true
    );

    define_reg_bool_option o_newCampaign(
        "NewCampaign",
        "registry:configuration:game:NewCampaign",
        "",
        true
    );

    define_reg_bool_option o_showIntro(
        "ShowIntro",
        "registry:configuration:game:ShowIntro",
        "",
        true
    );

    define_reg_option *options[] {
        &o_version,
        &o_gameSpeed,
        &o_fogOfWar,
        &o_impenetrableWalls,
        &o_goldDensity,
        &o_gameDuration,
        &o_loseHeartType,
        &o_maxCreatures,
        &o_manaRegeneration,
        &o_newCampaign,
        &o_showIntro,
    };

    Reg2CfgOptions r2c("dk2:Cfg", "Game", options, ARRAYSIZE(options));

}


namespace registry::dk2::configuration {

    define_reg_int_option o_version(
        "Version Number",
        "registry:configuration:Version_Number",
        "DKII registry config version\n",
        11
    );

    define_reg_option *options[] {
        &o_version,
    };

    Reg2CfgOptions r2c("dk2", "Configuration", options, ARRAYSIZE(options));

}



namespace registry::dk2 {


    define_reg_int_option o_language(
        "Language",
        "registry:Language",
        "DKII language\n",
        9
    );

    define_reg_int_option o_versionNumberMajor(
        "Version Number Major",
        "registry:Version_Number_Major",
        "",
        1
    );

    define_reg_int_option o_versionNumberMinor(
        "Version Number Minor",
        "registry:Version_Number_Minor",
        "",
        7
    );

    define_reg_option *options[] {
        &o_language,
        &o_versionNumberMajor,
        &o_versionNumberMinor,
    };

    Reg2CfgOptions r2c("", "dk2", options, ARRAYSIZE(options));

}

Reg2Cfg *patch::registry_to_config::createRoot(const std::string &name) {
    if (name != "Dungeon Keeper II") {
        printf("[err] invalid root \"%s\"\n", name.c_str());
        return NULL;
    }
    // printf("[r2c] createRoot \"%s\"\n", name.c_str());
    return &registry::dk2::r2c;
}
void patch::registry_to_config::close(Reg2Cfg *r2c) {
    if (r2c->builtin) return;
    printf("[%s] close %p\n", r2c->path.c_str(), r2c);
    delete r2c;
}

Reg2Cfg *r2c_openBuiltin(Reg2Cfg *r2c, const std::string &name) {
    if (r2c == &registry::dk2::r2c) {
        using namespace registry::dk2;
        if (name == configuration::r2c.name) return &configuration::r2c;
    } else if (r2c == &registry::dk2::configuration::r2c) {
        using namespace registry::dk2::configuration;
        if (name == paths::r2c.name) return &paths::r2c;
        if (name == video::r2c.name) return &video::r2c;
        if (name == player::r2c.name) return &player::r2c;
        if (name == network::r2c.name) return &network::r2c;
        if (name == sound::r2c.name) return &sound::r2c;
        if (name == game::r2c.name) return &game::r2c;
    }
    return nullptr;
}
Reg2Cfg *patch::registry_to_config::createSubCfg(Reg2Cfg *r2c, const std::string &name) {
    if (auto *sub = r2c_openBuiltin(r2c, name)) return sub;
    auto sub = new Reg2Cfg(r2c->path, name);
    gdata[sub->path] = std::vector<uint8_t>();
    printf("[%s:%s] createSubCfg %p\n", r2c->path.c_str(), name.c_str(), r2c);
    return sub;
}
Reg2Cfg *patch::registry_to_config::openSubCfg(Reg2Cfg *r2c, const std::string &name) {
    if (auto *sub = r2c_openBuiltin(r2c, name)) return sub;
    Reg2Cfg *sub = nullptr;
    auto it = gdata.find(r2c->path);
    if (it != gdata.end()) sub = new Reg2Cfg(r2c->path, name);
    printf("[%s:%s] openSubCfg %p\n", r2c->path.c_str(), name.c_str(), sub);
    return sub;
}

bool r2c_writeBytes_impl(Reg2Cfg *r2c, const std::string &field, const void *data, size_t size) {
    std::vector<uint8_t> vec;
    vec.resize(size);
    memcpy(vec.data(), data, size);
    gdata[r2c->path + ':' + field] = vec;
    return true;
}
bool patch::registry_to_config::writeBytes(Reg2Cfg *r2c, const std::string &field, const void *data, size_t size) {
    if (r2c->builtin && r2c->writeBytes(field, data, size)) return true;
    printf("[%s] writeBytes \"%s\" sz=%d\n", r2c->path.c_str(), field.c_str(), size);
    return r2c_writeBytes_impl(r2c, field, data, size);
}
size_t patch::registry_to_config::readBytesSize(Reg2Cfg *r2c, const std::string &field) {
    if (r2c->builtin) {
        size_t size = r2c->readBytesSize(field);
        if (size != 0) return size;
    }
    auto it = gdata.find(r2c->path + ':' + field);
    size_t size = 0;;
    if (it != gdata.end()) size = it->second.size();
    printf("[%s] readBytesSize \"%s\": %d\n", r2c->path.c_str(), field.c_str(), size);
    return size;
}
bool r2c_readBytes_impl(Reg2Cfg *r2c, const std::string &field, void *data, size_t size) {
    auto it = gdata.find(r2c->path + ':' + field);
    if (it == gdata.end()) return false;
    if (size) {
        memcpy(data, it->second.data(), min(it->second.size(), size));
    } else {
        memcpy(data, it->second.data(), it->second.size());
    }
    return true;
}

bool patch::registry_to_config::readBytes(Reg2Cfg *r2c, const std::string &field, void *data, size_t size) {
    if (r2c->builtin && r2c->readBytes(field, data, size)) return true;
    bool result = r2c_readBytes_impl(r2c, field, data, size);
    if (result) {
        printf("[%s] readBytes \"%s\" sz=%d\n", r2c->path.c_str(), field.c_str(), size);
    } else {
        printf("[%s] readBytes \"%s\" sz=%d: failed\n", r2c->path.c_str(), field.c_str(), size);
    }
    return result;
}

bool patch::registry_to_config::writeInt(Reg2Cfg *r2c, const std::string &field, int value) {
    if (r2c->builtin && r2c->writeInt(field, value)) return true;
    printf("[%s] writeInt \"%s\" value=%d\n", r2c->path.c_str(), field.c_str(), value);
    return r2c_writeBytes_impl(r2c, field, &value, sizeof(value));
}
bool patch::registry_to_config::readInt(Reg2Cfg *r2c, const std::string &field, int &value) {
    if (r2c->builtin && r2c->readInt(field, value)) return true;
    bool result = r2c_readBytes_impl(r2c, field, &value, sizeof(value));
    if (result) {
        printf("[%s] readInt \"%s\": %d\n", r2c->path.c_str(), field.c_str(), value);
    } else {
        printf("[%s] readInt \"%s\": failed\n", r2c->path.c_str(), field.c_str());
    }
    return result;
}

bool patch::registry_to_config::writeGuid(Reg2Cfg *r2c, const std::string &field, const GUID *value) {
    if (r2c->builtin && r2c->writeGuid(field, value)) return true;
    printf("[%s] writeGuid \"%s\"\n", r2c->path.c_str(), field.c_str());
    return r2c_writeBytes_impl(r2c, field, value, sizeof(GUID));
}
bool patch::registry_to_config::readGuid(Reg2Cfg *r2c, const std::string &field, GUID *value) {
    if (r2c->builtin && r2c->readGuid(field, value)) return true;
    bool result = r2c_readBytes_impl(r2c, field, value, sizeof(GUID));
    if (result) {
        printf("[%s] readGuid \"%s\"\n", r2c->path.c_str(), field.c_str());
    } else {
        printf("[%s] readGuid \"%s\": failed\n", r2c->path.c_str(), field.c_str());
    }
    return result;
}

bool patch::registry_to_config::writeString(Reg2Cfg *r2c, const std::string &field, const char *value) {
    if (r2c->builtin && r2c->writeString(field, value)) return true;
    printf("[%s] writeString \"%s\" value=\"%s\"\n", r2c->path.c_str(), field.c_str(), value);
    return r2c_writeBytes_impl(r2c, field, value, strlen(value));
}
bool patch::registry_to_config::readString(Reg2Cfg *r2c, const std::string &field, char *buf, size_t bufSize) {
    if (r2c->builtin && r2c->readString(field, buf, bufSize)) return true;
    bool result = r2c_readBytes_impl(r2c, field, buf, bufSize);
    if (result) {
        printf("[%s] readString \"%s\" bufSz=%d: \"%s\"\n", r2c->path.c_str(), field.c_str(), bufSize, buf);
    } else {
        printf("[%s] readString \"%s\" bufSz=%d: failed\n", r2c->path.c_str(), field.c_str(), bufSize);
    }
    return result;
}

