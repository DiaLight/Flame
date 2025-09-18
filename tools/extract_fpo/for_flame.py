import argparse
import bisect
import dataclasses
import pathlib
import re
import sys
import typing

import my_pdb
from my_fpo import MyFpoFun, fpobin_serialize, MySpdType, fpomap_serialize


@dataclasses.dataclass
class PdbProc:
    rva: int
    size: int
    name: str

    def __repr__(self):
        return f'{self.rva:X}-{self.rva + self.size:X} {self.name}'

def find_le(symbols_map: list[PdbProc], rva: int) -> PdbProc:
    idx = bisect.bisect_right(symbols_map, rva, key=lambda e: e.rva) - 1
    if idx == -1:
        return None
    return symbols_map[idx]


def pdb_extract_espmap(flame_pdb_file: pathlib.Path) -> list[MyFpoFun]:
    with open(flame_pdb_file, 'rb') as f:
        _data = f.read()
    pdb = my_pdb.MyPdb(_data)

    pdb_symbols_map: list[PdbProc] = []
    for mod in pdb.mod_symbols:
        for sym in mod.symbols:
            if my_pdb.CV_Thunk32Sym.match(sym.ty):
                proc = typing.cast(my_pdb.CV_Thunk32Sym, sym)
                sec = pdb.section_headers.sections[proc.segment - 1]
                rva = sec.VirtualAddress + proc.offset
                pdb_symbols_map.append(PdbProc(rva, proc.size, proc.name))
            if my_pdb.CV_ProcSym.match(sym.ty):
                proc = typing.cast(my_pdb.CV_ProcSym, sym)
                sec = pdb.section_headers.sections[proc.segment - 1]
                rva = sec.VirtualAddress + proc.code_offset
                pdb_symbols_map.append(PdbProc(rva, proc.code_size, proc.name))
    pdb_symbols_map.sort(key=lambda e: e.rva)


    # print(f'{pdb.pdb_info.header.Version=:}')
    # print(f'{pdb.pdb_info.header.TimeDateStamp=:08X}')
    # print(f'{pdb.pdb_info.header.Age=:08X}')
    # print(f'{uuid.UUID(bytes=bytes(pdb.pdb_info.header.GUID))}')
    # print(f'{pdb.pdb_info.header.cbNames=:08X}')

    pdb_dir = flame_pdb_file.parent / 'pdb'
    pdb_dir.mkdir(exist_ok=True)
    # for idx in pdb.root.streams.keys():
    #   suffix = pdb._stream_names.get(idx, '')
    #   suffix = suffix.replace('/', '_')
    #   suffix = suffix.replace('*', '_')
    #   (pdb_dir / f'{idx}_{suffix}.bin').write_bytes(pdb.root[idx])

    result: list[MyFpoFun] = []
    # print(len(pdb.fpo.fpos))
    # print(len(pdb.new_fpo.fpos))
    fpos: list[my_pdb.FrameData] = pdb.fpo.fpos + pdb.new_fpo.fpos
    fpos.sort(key=lambda fd: fd.code_start)

    fpo_fun: MyFpoFun = None
    last_rva = None
    for fpo in fpos:
        spd = fpo.locals_size + fpo.saved_regs_size
        fpo_rva = fpo.code_start
        if last_rva is not None:
            assert fpo_rva >= last_rva
        last_rva = fpo_rva
        proc = find_le(pdb_symbols_map, fpo_rva)
        assert proc is not None

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
        if fpo_fun is None or fpo_fun.rva != proc.rva:
            fpo_fun = MyFpoFun(proc.rva, proc.name)
            fpo_fun.size = proc.size
            result.append(fpo_fun)
            fpo_fun._ty = fpo.ty
            if fpo.ty is my_pdb.FrameType.FrameData:
                assert fpo.is_function_start
        assert fpo_fun.contains(fpo_rva)

        if fpo.ty is my_pdb.FrameType.Fpo:
            spd_ty = MySpdType.Fpo
        else:
            assert fpo.ty is my_pdb.FrameType.FrameData
            spd_ty = MySpdType.Frm
        fpo_fun.add_pdb(fpo_rva, fpo_rva + fpo.code_size, spd, flags, spd_ty, fpo.program)


    # with open(flame_pdb_file.parent / f'mod_infos.map', 'w') as f:
    #   for mi in pdb.debug.ModInfos:
    #     f.write(f'opened={mi.header.opened:<2}'
    #             f' r.offs={mi.header.range.Off:08X} r.sz={mi.header.range.Size:<4X} r.isec={mi.header.range.ISect:<2}'
    #             f' flags={mi.header.flags:08X}'
    #             f' mod_sym_sn={mi.header.ModuleSymStream:<3} mod_sym_sz={mi.header.SymByteSize:<5X}'
    #             f' old_line_sz={mi.header.oldLineSize} line_sz={mi.header.lineSize:<5X}'
    #             f' src_num={mi.header.nSrcFiles:<3} offss={mi.header.offsets:08X}'
    #             f' src_ni={mi.header.niSource:<4} comp_ni={mi.header.niCompiler:<4}'
    #             f' \n')

    # with open(flame_pdb_file.parent / f'contrib.map', 'w') as f:
    #   for sec in pdb.debug.SectionContrib.sections:
    #     f.write(f'{sec.ISect:X}+{sec.Off:<4X} sz={sec.Size:<4X}'
    #             f' chars={sec.Characteristics:08X} imod={sec.Imod:<4X}'
    #             f' dcrc={sec.DataCrc:08X} rcrc={sec.RelocCrc:08X}\n')


    # print('root.streams', len(pdb.root.streams), list(pdb.root.streams.keys()))
    # print('prev_root_delta', len(pdb.prev_root_delta.streams), list(pdb.prev_root_delta.streams.keys()))

    # section_hdr = pdb.root[pdb.debug.DBIDbgHeader.snSectionHdr]

    # pdb refs
    # https://github.com/microsoft/microsoft-pdb/blob/master/pdbdump/pdbdump.cpp#L2772
    # https://github.com/moyix/pdbparse/blob/master/pdbparse/__init__.py#L25
    # https://llvm.org/docs/PDB/MsfFile.html
    # https://en.wikipedia.org/wiki/Program_database
    # https://github.com/modesttree/Zenject/blob/master/NonUnityBuild/Zenject-Cecil/symbols/pdb/Microsoft.Cci.Pdb/PdbFile.cs#L356
    # https://github.com/getsentry/pdb/blob/master/src/framedata.rs#L99
    return result


def parse_map_file(msvcmap_file: pathlib.Path):
    with open(msvcmap_file, 'r') as f:
        map_lines = f.readlines()

    image_base: int = None
    symbols_map: list[tuple[int, str]] = []
    msvc_map_line = re.compile(' \\d{4}:[\\da-f]{8}\\s+(\\S+)\\s+([\\da-f]{8}) .{3} (\\S+)')
    for line in map_lines:
        line = line.rstrip()
        m = msvc_map_line.match(line)
        if m is None:
            continue
        va = int(m.group(2), 16)
        name = m.group(1)
        obj_file = m.group(3)
        if va == 0:
            continue
        if (va & 0xFF000000) == 0xFF000000:
            continue
        if name == '___ImageBase':
            image_base = va
            continue
        if name.startswith('$'):
            continue
        if obj_file == '<absolute>':
            continue
        rva = None
        if image_base is not None:
            rva = va - image_base
            if rva == 0:
                continue
        # print(f'{va:08X} {name}')
        if not obj_file.endswith('.cpp.obj'):
            name = obj_file + ':' + name
        symbols_map.append((va, name))
    return image_base, symbols_map


def main(pdb_file: pathlib.Path, fpo_file: pathlib.Path):
    fpos = pdb_extract_espmap(pdb_file)
    with fpo_file.open('wb') as f:
        fpobin_serialize(f, fpos)
    with fpo_file.with_name(fpo_file.name + '.map').open('w') as f:
        fpomap_serialize(f, fpos)


def start():
    parser = argparse.ArgumentParser()
    # in
    parser.add_argument('-pdb_file', type=str, required=True)
    # out
    parser.add_argument('-fpo_file', type=str, required=True)
    args = parser.parse_args()
    # print(' '.join(sys.argv))
    main(
        pathlib.Path(args.pdb_file),
        pathlib.Path(args.fpo_file),
    )


if __name__ == '__main__':
    start()
