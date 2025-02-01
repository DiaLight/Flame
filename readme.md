# Flame

Flame modifies the Dungeon Keeper 2 code to fix the bugs found in both single and multiplayer.
It works with the Disk, Steam and GOG versions of the game.

Warning: Saves and network sessions between Flame and non-Flame Dungeon Keeper 2 versions are [incompatible](https://github.com/DiaLight/Flame/issues/57).
But you can use `-original_compatible` flag to disable some patches that breaks compatibility.

## How to report a bug

1) If you have any bugs in the game, please describe them in the discord channel: https://discord.gg/RvrQpCFUZc or in the GitHub issues.
2) It helps a lot if you include steps how to reproduce found bug
3) Attaching a good test map is welcome

If you reporting several bugs, please split them to several Discord messages / GitHub issues. Please, be sure to have followed the recommended installation steps.

### What bugs are in priority to fix?
Imagine you are playing through a storyline campaign and there are moments
that are extremely frustrating or simply prevent you from progressing further in the game.
These bugs, I consider them critical, and those are the ones I will focus on fixing.

You can vote for an bug that you consider critical at your discretion by placing a rocket emoji(?) on the corresponding issue


## How to install
1) Go to the [releases](https://github.com/DiaLight/Flame/releases) page and download the Flame-1.7.0-*.zip file of the newest release
2) Extract the zip file into your Dungeon Keeper 2 game directory

Now run `DKII-Flame-1.7.0-*.exe` to play. It is possible to rename the .exe file to play Multiplayer via GameRanger.

Note: It is possible to find newer test builds on [github actions](https://github.com/DiaLight/Flame/actions)

Note 2: The `Data` directory are not required for this to work, but are recommended.

## Files explained

The `Data` folder in the zip file contains patches for some campaign maps taken from the link https://keeperklan.com/downloads.php?do=file&id=141. These fix creatures like Dark Angels not spawning in some campaign maps.

# For Software Developers

## How it is done

Flame is a new approach to modifying the compiled code of Dungeon Keeper 2

Flame recompiles some functions of `DKII.EXE` into a separate `.exe` file.
Then it merges this file with the original `.exe` file, replacing the references to
the original functions with the references to recompiled functions.
Recompiled functions are supplemented with switchable changes that fix some game bugs

[Earlier](https://github.com/DiaLight/Flame/tree/46e5b0c1df93060bd01a83bb6d14d064e9c8c3dc "Full relinking approach"), this project implemented an approach to fully relinking `DKII.EXE`,
which contains false positive references that caused new bugs. Due to problems with false positive references, the relinking method was replaced by the exe merge method.

## Build requirements
- CMake 3.25 or higher https://cmake.org/download/
- Visual Studio 2022
- Dungeon Keeper II v1.70 (GOG/Steam version)
- Python 3 https://www.python.org/downloads/windows/

## How to build
- `mkdir build && cd build`
- `"D:\Program Files\Visual Studio Community\2022\VC\Auxiliary\Build\vcvars32.bat"`
- `cmake -DCMAKE_BUILD_TYPE=Release -GNinja -DCMAKE_INSTALL_PREFIX=../install ..`
- `cmake --build .`
- `cmake --install .`
- `copy "..\install\DKII-Flame-<version>.exe" "<Dungeon Keeper2 dir>/DKII-Flame.exe"`