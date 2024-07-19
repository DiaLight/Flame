
### Introduction
Based on the reverse, I decided that the compiler `msvc` was used in the build of Dungeon Keeper 2 and I tailor all the rebuilding processes specifically for it.
Since the official build of Dungeon Keeper 2, the basic principles of the standard compilation have not changed.

The process of compiling `.cpp` source files into the final `.exe` file has an intermediate step.
First, all `.cpp` files, each in its own process, are compiled single-threaded into `.obj` files by the `cl.exe` compiler.
For each `.dll` file that can be linked to, there is a separate `.lib` file.
After compilation, the linker `link.exe` takes all the compiled `.obj` files and additionally linked `.lib` files and merges them all into a `.exe` file if all links between `.obj` files have been satisfied.

In the case of standard compilation, `.obj` files are in `COFF` format and contain machine code and global(+static) variables,
which does not changes during linking, with the exception of editing connections between functions and data.

In modern compilation there are more advanced scenarios where `LTO`(Link Time Optimization) is used.
In this scenario, `.obj` files store `IR`(Intermediate Representation) bytecode instead of compiled machine code.
This way, more efficient optimizations can be applied when linking. but this is not our case.

`.lib` files can be thought of as archives containing many `.obj` files. At the same time, `.obj` files can also describe the dependence on the exported symbols of any `.dll` file.
Many functions and data can be declared in `.cpp` files. Accordingly, one `.obj` file can contain many functions and data units.

The `.exe` file stores the compiled machine code and data.
If you collect information about the relationships between functions and data, you can try to return them back to `.obj` files.
And then recompile with the changes.

### Terms used in the project
For each function and data unit, a byte array and `IMAGE_SECTION_HEADER` which describes it are created in the `.obj` file.
In my code, I call such a unit of code or data `Chunk`(tools/delinker/chunk/Chunk.h).
`Chunk` is an array of bytes(Chunk::data) with information about whether this data can be read, written and executed(Chunk::chars).
`Chunk` also stores information about connections between chunks(Chunk::refs, Chunk::xrefs).

Known functions and data are called `Global`(mapping/sgmap/Global.h).
Each `Global` represents data mapping with detailed information about the data type.
So detailed that `cpp` headers can be generated from them.

Mapping of `Global` data is obtained through reverse engineering in `Ida PRO`(mapping/ida/sgmap_ida.py).
Mapping of connections between `Chunk` objects is also achieved through reverse engineering in `Ida PRO`(mapping/ida/references_ida).
Alas, I have not yet found a way to synchronize reverse work in `git` between different researchers.
There was an option to synchronize via `.idc` dump. Unfortunately, the `.idc` dump preserves the types, but does not preserve the tree structure of the types.

### How it works
In `DKII.EXE` version 1.7.0 there are sections:
```
# access: R-read, W-write, X-execute
<va from>-<va to> <access> <name>
00401000-00652AA2 R-X .text
00653000-0066BE1A R-X cseg
0066C000-0068D53C R-- .rdata
0068E000-006CCA20 RW- .data
006CCA20-007A6DD0 RW- .data    uninitialized
007A7000-007A7730 RW- grpoly_d
007A8000-007ACACC RW- uva_data
007AD000-007AE658 RW- idct_dat
007AF000-007AFA00 RW- tqia_dat
007B0000-007B1004 RW- dseg
007B2000-007B2400 RW- lbmpeg_d
007B3000-007B5F30 R-- .rsrc
```
I place each section in `Chunk` and use previously collected connections between chunks from mapping(mapping/references.map).
This is already enough to generate `.obj` files through the builder(tools/delinker/CoffBuilder.cpp).
But when linking, such an exe file will not work.
To work, you need to cut out the imports from `.rdata` and declare them again so that the linker links them with existing `.dll` in the system.
You also need to somehow call the entry point of the program and in theory the exe will work.
At this stage we will have 12 `.obj` files and each will be assembled from one `Chunk` object.
But this is not enough to replace one function or one global variable.

The next step is to collect `Global` objects from mapping(mapping/DKII_EXE_v170.sgmap) and using these objects I split `Chunk` objects into parts.
This is how we got sliced `Chunk` objects, each with its own name, with the cutting detail that reverse researchers were able to achieve.

To carry out substitution of functions and data, it is necessary to exclude the desired `Chunk` objects from the delinking process using mapping(src/replace_globals.map).
So we will have missing functions and data during linking and we will get a linking error.
After that, we will write them manually with the correct naming and add our .cpp files to the linking.

This way we get a project with partially decompiled source code that can be compiled back into a working `.exe`.
Changing written source files does not require special skills, unlike point binary patches.
This is the convenience that I could not achieve in the `Ember` project.
