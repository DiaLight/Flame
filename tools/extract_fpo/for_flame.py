import argparse
import bisect
import pathlib
import re
import sys

import my_pdb
from my_fpo import MyFpoFun, fpobin_serialize


def find_le(symbols_map: list[tuple[int, str]], va: int) -> tuple[int, str]:
    idx = bisect.bisect_right(symbols_map, va, key=lambda e: e[0]) - 1
    if idx == -1:
        return None
    return symbols_map[idx]


def pdb_extract_espmap(
        flame_pdb_file: pathlib.Path,
        symbols_map: list[tuple[int, str]],
        delta: int = 0
) -> list[MyFpoFun]:
    with open(flame_pdb_file, 'rb') as f:
        _data = f.read()
    flame_pdb = my_pdb.MyPdb(_data)

    # print(f'{flame_pdb.pdb_info.header.Version=:}')
    # print(f'{flame_pdb.pdb_info.header.TimeDateStamp=:08X}')
    # print(f'{flame_pdb.pdb_info.header.Age=:08X}')
    # print(f'{uuid.UUID(bytes=bytes(flame_pdb.pdb_info.header.GUID))}')
    # print(f'{flame_pdb.pdb_info.header.cbNames=:08X}')

    pdb_dir = flame_pdb_file.parent / 'pdb'
    pdb_dir.mkdir(exist_ok=True)
    # for idx in flame_pdb.root.streams.keys():
    #   suffix = flame_pdb._stream_names.get(idx, '')
    #   suffix = suffix.replace('/', '_')
    #   suffix = suffix.replace('*', '_')
    #   (pdb_dir / f'{idx}_{suffix}.bin').write_bytes(flame_pdb.root[idx])

    result: list[MyFpoFun] = []
    # print(len(flame_pdb.fpo.fpos))
    # print(len(flame_pdb.new_fpo.fpos))
    # fpos: list[my_pdb.FrameData] = flame_pdb.fpo.fpos + flame_pdb.new_fpo.fpos
    # fpos: list[my_pdb.FrameData] = flame_pdb.fpo.fpos
    fpos: list[my_pdb.FrameData] = flame_pdb.new_fpo.fpos
    fpos.sort(key=lambda fd: fd.code_start)

    # with open(flame_pdb_file.parent / f'frames.map', 'w') as f:
    #   for fpo in fpos:
    #     spd = fpo.locals_size + fpo.saved_regs_size
    #     e = find_le(symbols_map, fpo.code_start + delta)
    #     fun_va, fun_name = (0, '') if e is None else e
    #     fpo_va = fpo.code_start + delta
    #     flags = [
    #       'F' if fpo.is_function_start else ' ',
    #       'S' if fpo.has_structured_eh else ' ',
    #       'C' if fpo.has_cpp_eh else ' ',
    #       'B' if fpo.uses_base_pointer else ' ',
    #     ]
    #     flags = ''.join(flags)
    #     max_stack = fpo.max_stack_size if fpo.max_stack_size is not None else 'N'
    #     f.write(f'{fun_va:08X} {fpo_va:08X}-{fpo_va + fpo.code_size:08X}'
    #           f'  {fpo_va-fun_va:04X}-{fpo_va + fpo.code_size-fun_va:04X}'
    #           f'  spd={spd:04X} {flags} {fpo.ty.name:<10s}'
    #           f' msx_stack={max_stack}'
    #           f' "{fun_name}"\n')

    fpo_fun: MyFpoFun = None
    for fpo in fpos:
        spd = fpo.locals_size + fpo.saved_regs_size
        e = find_le(symbols_map, fpo.code_start + delta)
        fun_va, fun_name = (0, '') if e is None else e
        fpo_va = fpo.code_start + delta
        flags = 0
        if fpo.is_function_start:
            flags |= 1
        if fpo.has_structured_eh:
            flags |= 2
        if fpo.has_cpp_eh:
            flags |= 4
        if fpo.uses_base_pointer:
            flags |= 8

        assert fpo.ty in [my_pdb.FrameType.Fpo, my_pdb.FrameType.FrameData]
        if fpo_fun is None or fpo_fun.va != fun_va:
            fpo_fun = MyFpoFun(fun_va, fun_name)
            result.append(fpo_fun)
            fpo_fun._ty = fpo.ty
            if fpo.ty is my_pdb.FrameType.FrameData:
                assert fpo.is_function_start

        if fpo_fun._ty is my_pdb.FrameType.Fpo:
            if fpo.ty is my_pdb.FrameType.Fpo:
                if fpo_fun.spds:
                    assert fpo_va >= fpo_fun.va + fpo_fun.spds[-1].offs
                fpo_fun.add_fpo(fpo_va, fpo_va + fpo.code_size, spd, flags)
                assert fpo_fun.spds
            else:
                assert fpo.ty is my_pdb.FrameType.FrameData
                print(fpo.ty.name)
                assert False
        else:
            if fpo.ty is my_pdb.FrameType.Fpo:
                assert fpo_fun._ty is my_pdb.FrameType.FrameData
                print(fpo.ty.name)
                assert spd == 0
            else:
                assert fpo.ty is my_pdb.FrameType.FrameData
                fpo_fun.add_frm(fpo_va, fpo_va + fpo.code_size, spd, flags)

        # max_stack = fpo.max_stack_size if fpo.max_stack_size is not None else 'n'

        # print(f'{fpo.ty.name:<10s} offs={fpo.code_start:08X} sz={fpo.code_size:<4X}'
        #       f' spd={fpo.locals_size + fpo.saved_regs_size:<4X} locals={fpo.locals_size:<4X} saved_regs={fpo.saved_regs_size:<4X}'
        #
        #       f' params={fpo.params_size:<4X} prolog={fpo.prolog_size:<4X}'
        #
        #       f' msx_stack={fpo.max_stack_size} seh={fpo.has_structured_eh:d} cppeh={fpo.has_cpp_eh:d}'
        #       f' isfun={fpo.is_function_start:d} use_bp={fpo.uses_base_pointer:d} program={fpo.program}'
        # )
        # result.append()


    # with open(flame_pdb_file.parent / f'mod_infos.map', 'w') as f:
    #   for mi in flame_pdb.debug.ModInfos:
    #     f.write(f'opened={mi.header.opened:<2}'
    #             f' r.offs={mi.header.range.Off:08X} r.sz={mi.header.range.Size:<4X} r.isec={mi.header.range.ISect:<2}'
    #             f' flags={mi.header.flags:08X}'
    #             f' mod_sym_sn={mi.header.ModuleSymStream:<3} mod_sym_sz={mi.header.SymByteSize:<5X}'
    #             f' old_line_sz={mi.header.oldLineSize} line_sz={mi.header.lineSize:<5X}'
    #             f' src_num={mi.header.nSrcFiles:<3} offss={mi.header.offsets:08X}'
    #             f' src_ni={mi.header.niSource:<4} comp_ni={mi.header.niCompiler:<4}'
    #             f' \n')

    # with open(flame_pdb_file.parent / f'contrib.map', 'w') as f:
    #   for sec in flame_pdb.debug.SectionContrib.sections:
    #     f.write(f'{sec.ISect:X}+{sec.Off:<4X} sz={sec.Size:<4X}'
    #             f' chars={sec.Characteristics:08X} imod={sec.Imod:<4X}'
    #             f' dcrc={sec.DataCrc:08X} rcrc={sec.RelocCrc:08X}\n')


    # print('root.streams', len(flame_pdb.root.streams), list(flame_pdb.root.streams.keys()))
    # print('prev_root_delta', len(flame_pdb.prev_root_delta.streams), list(flame_pdb.prev_root_delta.streams.keys()))
    print('present', len(flame_pdb.pdb_info.present), flame_pdb.pdb_info.present)

    # section_hdr = flame_pdb.root[flame_pdb.debug.DBIDbgHeader.snSectionHdr]

    # pdb refs
    # https://github.com/microsoft/microsoft-pdb/blob/master/pdbdump/pdbdump.cpp#L2772
    # https://github.com/moyix/pdbparse/blob/master/pdbparse/__init__.py#L25
    # https://llvm.org/docs/PDB/MsfFile.html
    # https://en.wikipedia.org/wiki/Program_database
    # https://github.com/modesttree/Zenject/blob/master/NonUnityBuild/Zenject-Cecil/symbols/pdb/Microsoft.Cci.Pdb/PdbFile.cs#L356
    # https://github.com/getsentry/pdb/blob/master/src/framedata.rs#L99
    return result


def collect_replace_info(msvcmap_file: pathlib.Path):
    with open(msvcmap_file, 'r') as f:
        map_lines = f.readlines()

    image_base: int = None
    msvcmap = {}
    msvc_map_line = re.compile(' \\d{4}:[\\da-f]{8}\\s+(\\S+)\\s+([\\da-f]{8}) .{3} (\\S+)')
    for line in map_lines:
        line = line.rstrip()
        m = msvc_map_line.match(line)
        if m is None:
            continue
        flame_va = int(m.group(2), 16)
        name = m.group(1)
        obj_file = m.group(3)
        if flame_va == 0:
            continue
        if name == '___ImageBase':
            image_base = flame_va
            continue
        if image_base is not None:
            flame_rva = flame_va - image_base
            if flame_rva == 0:
                continue
        # print(f'{flame_va:08X} {name}')
        if name in msvcmap:
            if (not name.startswith('??__')
                    and not name.startswith('__guard')
                    and not name.startswith('__ehfuncinfo')
                    and not name.startswith('__unwindfunclet')
                    and not name.startswith('__ehhandler')
                    and not name.startswith('__unwindtable')
                    and not name.startswith('__catch')
                    and not name.startswith('__tryblocktable')
                    and not name.startswith('$')
                    and not name.endswith('VLCtable@@A')):
                pass
                # print(f'duplicate {flame_va:08X} {flame_map[name]:08X} {name}')
                # raise Exception()
        if not obj_file.endswith('.cpp.obj'):
            name = obj_file + ':' + name
        msvcmap[name] = flame_va
    return msvcmap


def main(pdb_file: pathlib.Path, map_file: pathlib.Path, fpo_file: pathlib.Path):
    flame_map = collect_replace_info(map_file)
    symbols_map: list[tuple[int, str]] = []
    for name, va in flame_map.items():
        symbols_map.append((va, name))
    fpos = pdb_extract_espmap(pdb_file, symbols_map)
    with fpo_file.open('wb') as f:
        fpobin_serialize(f, fpos)


def start():
    parser = argparse.ArgumentParser()
    # in
    parser.add_argument('-pdb_file', type=str, required=True)
    parser.add_argument('-map_file', type=str, required=True)
    # out
    parser.add_argument('-fpo_file', type=str, required=True)
    args = parser.parse_args()
    print(' '.join(sys.argv))
    main(
        pathlib.Path(args.pdb_file),
        pathlib.Path(args.map_file),
        pathlib.Path(args.fpo_file),
    )


if __name__ == '__main__':
    start()
