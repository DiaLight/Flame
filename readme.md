Flame is a new approach to modifying compiled code Dungeon Keeper 2

Flame recompiles some functions of `DKII.EXE` into a separate `.exe` file.
Then it merges this file with the original `.exe` file, replacing the references to
the original functions with the references to recompiled functions.
Recompiled functions are supplemented with switchable changes that fix some game bugs

[Earlier](https://github.com/DiaLight/Flame/tree/46e5b0c1df93060bd01a83bb6d14d064e9c8c3dc "Full relinking approach"), this project implemented an approach to fully relinking `DKII.EXE`,
which contains false positive references that caused new bugs.

The latest build can be taken from the github actions

How to install:
- copy DKII-Flame-1.7.0-*.exe from github actions to game directory (no need rename to DKII-DX.exe or DKII.exe. exe name does not matter)
- (optional, but recommended) copy ddraw.dll from https://github.com/narzoul/DDrawCompat/releases/tag/v0.5.3 to game directory
- (optional, but recommended) copy dinput.dll from https://github.com/elishacloud/dinputto8/releases/tag/v1.0.54.0 to game directory
- run DKII-Flame-1.7.0-*.exe

Additional ddraw.dll and dinput.dll are fixing some graphical bugs and i think improve general stability.
I prefer not spending time on fixing something that already fixed by other developers.
When report issue please ensure that you are uses these dlls.
The Steam version of the game is installed along with these dlls

Build requirements:
- CMake 3.25 or higher https://cmake.org/download/
- Visual Studio 2022
- Dungeon Keeper II v1.70 (GOG/Steam version)
- Python 3 https://www.python.org/downloads/windows/

How to build:
- `mkdir build && cd build`
- `"D:\Program Files\Visual Studio Community\2022\VC\Auxiliary\Build\vcvars32.bat"`
- `cmake -DCMAKE_BUILD_TYPE=Release -GNinja -DCMAKE_INSTALL_PREFIX=../install ..`
- `cmake --build .`
- `cmake --install .`
- `copy "..\install\DKII-Flame-<version>.exe" "<Dungeon Keeper2 dir>/DKII-Flame.exe"`
