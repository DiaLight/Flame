import enum
import io
import pathlib
import my_pdb
import bisect


class MySpdType(enum.IntEnum):
  Ida = 0
  Fpo = 1
  Frm = 2


class MySpd:  # spd - esp delta

  def __init__(self, offs, spd, ty: MySpdType, kind: int):
    self.offs = offs
    self.spd = spd
    self.ty = ty
    self.kind = kind


class MyFpoFun:

  def __init__(self, va, name):
    self.va = va
    self.name = name
    self.spds: list[MySpd] = []
    self.size = 0

    self._ty: my_pdb.FrameType = None

  def _update_size(self, size):
    if size > self.size:
      self.size = size

  def _add(self, my_spd: MySpd):
    bisect.insort(self.spds, my_spd, key=lambda mspd: mspd.offs)

  def _find_ge(self, offs) -> MySpd or None:
    idx = bisect.bisect_left(self.spds, offs, key=lambda mspd: mspd.offs)
    if idx >= len(self.spds):
      return None
    return self.spds[idx]

  def add_ida(self, va, spd, kind: int):
    offs = va - self.va
    self._update_size(offs + 1)  # ida end is last ins start. dirty range fix
    self._add(MySpd(offs, spd, MySpdType.Ida, kind))

  def add_fpo(self, start_va, end_va, spd, flags: int):
    start_offs = start_va - self.va
    end_offs = end_va - self.va
    self._update_size(end_offs)
    my_spd: MySpd = self._find_ge(start_offs)
    if my_spd is not None:
      self._add(MySpd(start_offs, my_spd.spd, my_spd.ty, my_spd.kind))
    self._add(MySpd(end_offs - 1, spd, MySpdType.Fpo, flags))

  def add_frm(self, start_va, end_va, spd, flags: int):
    start_offs = start_va - self.va
    end_offs = end_va - self.va
    self._update_size(end_offs)
    my_spd: MySpd = self._find_ge(start_offs)
    if my_spd is not None:
      self._add(MySpd(start_offs, my_spd.spd, my_spd.ty, my_spd.kind))
    self._add(MySpd(end_offs - 1, spd, MySpdType.Frm, flags))


def read_espmap(dkii_espmap_file: pathlib.Path) -> list[MyFpoFun]:
  result: list[MyFpoFun] = []
  fpo = None
  for line in dkii_espmap_file.read_text().splitlines():
    if line.startswith('#'):
      continue
    if not line.startswith(' '):
      va, name = line.split(' ', 1)
      va = int(va, 16)
      fpo = MyFpoFun(va, name)
      result.append(fpo)
    else:
      assert fpo is not None
      line = line[1:]
      split = line.split(' ', 4)
      assert len(split) in [4, 5]
      va, spd, kind, delta, *cmt = split
      if kind == 'jmp':
        target = int(delta, 16)
        delta = 0
      va, spd, delta = int(va, 16), int(spd), int(delta)
      if kind == 'sp':
        kind = 0
      elif kind == 'jmp':
        kind = 1
      elif kind == 'ret':
        kind = 2
      else:
        raise Exception(kind)
      fpo.add_ida(va, -spd, kind)
  return result


def find_le(symbols_map: list[tuple[int, str]], va: int) -> tuple[int, str]:
  idx = bisect.bisect_right(symbols_map, va, key=lambda e: e[0]) - 1
  if idx == -1:
    return None
  return symbols_map[idx]


def pdb_extract_espmap(
    flame_pdb_file: pathlib.Path,
    symbols_map: list[tuple[int, str]], delta: int) -> list[MyFpoFun]:
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
  fpos: list[my_pdb.FrameData] = flame_pdb.fpo.fpos + flame_pdb.new_fpo.fpos
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
    # flags = [
    #   'F' if fpo.is_function_start else ' ',
    #   'S' if fpo.has_structured_eh else ' ',
    #   'C' if fpo.has_cpp_eh else ' ',
    #   'B' if fpo.uses_base_pointer else ' ',
    # ]
    # flags = ''.join(flags)
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
        assert False
    else:
      if fpo.ty is my_pdb.FrameType.Fpo:
        assert fpo_fun._ty is my_pdb.FrameType.FrameData
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


  # https://github.com/microsoft/microsoft-pdb/blob/master/pdbdump/pdbdump.cpp#L2772
  # https://github.com/moyix/pdbparse/blob/master/pdbparse/__init__.py#L25
  # https://llvm.org/docs/PDB/MsfFile.html
  # https://en.wikipedia.org/wiki/Program_database
  # https://github.com/modesttree/Zenject/blob/master/NonUnityBuild/Zenject-Cecil/symbols/pdb/Microsoft.Cci.Pdb/PdbFile.cs#L356
  # https://github.com/getsentry/pdb/blob/master/src/framedata.rs#L99
  return result


def write_varint(f, number):
  assert number >= 0
  while True:
    towrite = number & 0x7f
    number >>= 7
    if number:
      f.write(int.to_bytes(towrite | 0x80, 1, 'little'))
    else:
      f.write(int.to_bytes(towrite, 1, 'little'))
      break

def write_signed_varint(f, number):
  if number < 0:
    number = ((-number) << 1) | 1
  else:
    number = (number << 1) | 0
  write_varint(f, number)


def build_merged_binary_fpomap(
    dkii_espmap_file: pathlib.Path, flame_pdb_file: pathlib.Path,
    symbols_map: list[tuple[int, str]], delta: int) -> bytes:
  dkii_fpos = read_espmap(dkii_espmap_file)
  flame_fpos = pdb_extract_espmap(flame_pdb_file, symbols_map, delta)

  for mfpo in flame_fpos:
    print(f'{mfpo.va:08X} {mfpo.va + mfpo.size:08X} {mfpo.name}')
    for mspd in mfpo.spds:
      print(f' {mfpo.va + mspd.offs:08X} {mspd.spd:04X} {mspd.ty.name} {mspd.kind}')

  all_fpos = dkii_fpos + flame_fpos


  with io.BytesIO() as f:
    print(f'fposCount = {len(all_fpos)}')
    write_varint(f, len(all_fpos))
    last_va = 0
    for mfpo in all_fpos:
      write_varint(f, mfpo.va - last_va)
      write_varint(f, mfpo.size)
      f.write(mfpo.name.encode('ascii') + b'\x00')
      write_varint(f, len(mfpo.spds))
      for mspd in mfpo.spds:
        write_varint(f, mspd.offs)
        write_signed_varint(f, mspd.spd)
        write_varint(f, mspd.ty)
        write_varint(f, mspd.kind)
      last_va = mfpo.va
    return f.getvalue()

  # with io.BytesIO() as d:
  #   with io.BytesIO() as f:
  #     f.write(int.to_bytes(len(all_fpos), 4, 'little'))
  #     for mfpo in all_fpos:
  #       f.write(int.to_bytes(mfpo.va, 4, 'little'))
  #       f.write(int.to_bytes(mfpo.size, 4, 'little'))
  #
  #       f.write(int.to_bytes(d.tell(), 4, 'little'))
  #       d.write(mfpo.name.encode('ascii') + b'\x00')
  #
  #       f.write(int.to_bytes(d.tell(), 4, 'little'))
  #       d.write(int.to_bytes(len(mfpo.spds), 4, 'little'))
  #       for mspd in mfpo.spds:
  #         d.write(int.to_bytes(mspd.offs, 4, 'little'))
  #         d.write(int.to_bytes(mspd.spd, 4, 'little', signed=True))
  #         d.write(int.to_bytes(mspd.ty, 2, 'little'))
  #         d.write(int.to_bytes(mspd.kind, 2, 'little'))
  #     funs = f.getvalue()
  #   data = d.getvalue()
  # return funs + data
