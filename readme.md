Flame is a new approach to modifying compiled code Dungeon Keeper 2

Difference from the previous implementation(https://github.com/DiaLight/Ember):
* Ember converts `DKII.EXE` to `dk2.dll` and performs memory dot patches on it after the code has been loaded into memory.
* Flame parses `DKII.EXE` into `msvc` compatible `.obj` files. These files are replaced with other `.obj` files. Then they are compiled back into `DKII-Flame.EXE`

For a more detailed description of how Flame  works, read `how_it_works.md`

The latest build can be taken from the github actions

Requirements:
- CMake 3.25 or higher https://cmake.org/download/
- Visual Studio 2022
- Dungeon Keeper II v1.70
- Git https://git-scm.com/download/win
- Python 3 https://www.python.org/downloads/windows/
- GitPython https://pypi.org/project/GitPython/

How to build:
- `mkdir build && cd build`
- `"D:\Program Files\Visual Studio Community\2022\VC\Auxiliary\Build\vcvars32.bat"`
- `cmake -DCMAKE_BUILD_TYPE=Release -GNinja -DCMAKE_INSTALL_PREFIX=../install ..`
- `cmake --build .`
- `cmake --install .`
- `copy "..\install\DKII-Flame-<version>.exe" "<Dungeon Keeper2 dir>/DKII-Flame.exe"`
