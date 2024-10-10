# Flame
A new approach to modifying the compiled code of Dungeon Keeper 2

Flame recompiles some functions of `DKII.EXE` into a separate `.exe` file.
Then it merges this file with the original `.exe` file, replacing the references to
the original functions with the references to recompiled functions.
Recompiled functions are supplemented with switchable changes that fix some game bugs

[Earlier](https://github.com/DiaLight/Flame/tree/46e5b0c1df93060bd01a83bb6d14d064e9c8c3dc "Full relinking approach"), this project implemented an approach to fully relinking `DKII.EXE`,
which contains false positive references that caused new bugs.

## How to install
- download `flame.zip` file from github actions https://github.com/DiaLight/Flame/actions
- copy `DKII-Flame-1.7.0-*.exe` from `flame.zip` to game directory (no need rename to DKII-DX.exe or DKII.exe. exe name does not matter)
- (optional, but recommended) copy `Data` directory from `flame.zip` with replacement to the game directory
- (optional, but recommended) copy `ddraw.dll` from `flame.zip` to the game directory
- run `DKII-Flame-1.7.0-*.exe`

The `DKII-Flame-1.7.0-*.map` file in the `flame.zip` file you dont need to copy.
I need it if I suddenly need to debug an old build

The `Date` folder in the `flame.zip` file contains patches for some campaign maps taken from the link https://keeperklan.com/downloads.php?do=file&id=141

The `ddraw.dll` in the `flame.zip` file are taken from https://github.com/narzoul/DDrawCompat/releases/tag/v0.5.3
It fixing some graphical bugs and i think improve general stability.
This dll is especially needed for those who observe graphic artifacts when starting the game
or whose game crashes immediately upon starting any game level
The Steam version of the game is installed along with this `ddraw.dll`

If you have any bugs in the game, please describe them in the discord channel https://discord.gg/RvrQpCFUZc
When report issue please ensure that you are uses `ddraw.dll`

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
