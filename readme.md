Flame is a new approach to modifying compiled code Dungeon Keeper 2

Difference from the previous implementation(https://github.com/DiaLight/Ember):
* Ember converts `DKII.EXE` to `dk2.dll` and performs memory dot patches on it after the code has been loaded into memory.
* Flame parses `DKII.EXE` into `msvc` compatible `.obj` files. These files are replaced with other `.obj` files. Then they are compiled back into `DKII-Flame.EXE`

For a more detailed description of how Flame  works, read `how_it_works.md`

The latest build can be taken from the github actions

How to install:
- copy DKII-Flame-1.7.0-*.exe from github actions to game directory (no need to rename DKII-DX.exe or DKII.exe. exe name does not matter)
- copy ddraw.dll from https://github.com/narzoul/DDrawCompat/releases/tag/v0.5.3 to game directory
- copy dinput.dll from https://github.com/elishacloud/dinputto8/releases/tag/v1.0.54.0 to game directory
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
