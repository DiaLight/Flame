import argparse
import io
import os.path
import pathlib
import re
import ctypes
import sys
from ctypes import wintypes
import pe_types
import my_pe
import my_espmap


class ReplaceRefInfo:

  def __init__(self, name: str, target_va: int, new_va: int):
    self.name = name
    self.target_va = target_va
    self.target_xrefs: list[tuple[int, int, str]] = []
    self.new_va = new_va

  def __repr__(self):
    return f'RFI({self.target_va:08X}->{self.new_va:08X}, xrefs.len={len(self.target_xrefs)}, "{self.name}")'


def read_symbols(dkii_symmap_file: pathlib.Path) -> tuple[dict[str, int], dict[str, int]]:
  with open(dkii_symmap_file, 'r') as f:
    dkii_map_lines = f.readlines()
  dkii_map = {}
  to_replace = {}
  for line in dkii_map_lines:
    line = line.rstrip()
    if not line:
      continue
    split = line.split(' ')
    va = int(split[0], 16)
    name = split[1]
    is_replace = len(split) > 2 and split[2] == 'REPLACE'
    if is_replace:
      to_replace[name] = va
      name += '_replaced'
    dkii_map[name] = va
  return dkii_map, to_replace


def collect_replace_info(
    flame_msvcmap_file: pathlib.Path,
    to_replace: dict[str, int],
    replace_refs: list[ReplaceRefInfo],
    image_base: int
):
  with open(flame_msvcmap_file, 'r') as f:
    map_lines = f.readlines()

  flame_map = {}
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
    flame_rva = flame_va - image_base
    if flame_rva == 0:
      continue
    # print(f'{flame_va:08X} {name}')
    if name in flame_map:
      if (not name.startswith('??__')
          and not name.startswith('__guard')
          and not name.startswith('$')
          and not name.endswith('VLCtable@@A')):
        print(f'duplicate {flame_va:08X} {flame_map[name]:08X} {name}')
        raise Exception()
    if not obj_file.endswith('.cpp.obj'):
      name = obj_file + ':' + name
    flame_map[name] = flame_va
    dkii_va = to_replace.get(name, None)
    if dkii_va is None:
      continue
    del to_replace[name]
    replace_refs.append(ReplaceRefInfo(name, dkii_va, flame_va))
  if len(to_replace):
    print("not every replace function was implemented. missing functions:")
    for name, va in to_replace.items():
      print(f'{va:08X} {name}')
    raise Exception()
  return flame_map


def collect_xrefs(references_file: pathlib.Path) -> dict[int, list[tuple[int, int, str]]]:
  with open(references_file, 'r') as f:
    references_lines = f.readlines()
  dkii_xrefs = {}
  for line in references_lines:
    line = line.rstrip()
    if not line or line.startswith('#'):
      continue
    src_va, value, dst_va, kind = line.split(' ')
    src_va, value, dst_va, kind = int(src_va, 16), int(value, 16), int(dst_va, 16), kind
    dkii_xrefs.setdefault(dst_va, []).append((src_va, value, kind))
  return dkii_xrefs


class ImportTableBuild:

  def __init__(self, dll_name_rva, dll_name):
    self.dll_name_rva = dll_name_rva
    self.dll_name = dll_name
    self.funs = []
    self.thunks = None


def append_dll_sections_into_exe(dkii_data: bytes, flame_data: bytes) -> my_pe.MyPe:
  dkii_pe = my_pe.MyPe(dkii_data)
  flame_pe = my_pe.MyPe(flame_data)
  print(f'flame virtual space: {dkii_pe.nt.OptionalHeader.ImageBase:08X}-{dkii_pe.nt.OptionalHeader.ImageBase + dkii_pe.nt.OptionalHeader.SizeOfImage:08X}')
  print(f'dkii virtual space: {flame_pe.nt.OptionalHeader.ImageBase:08X}-{flame_pe.nt.OptionalHeader.ImageBase + flame_pe.nt.OptionalHeader.SizeOfImage:08X}')
  # validate some headers
  last = list(dkii_pe.sections)[-1]
  sections_virt_end = my_pe.align_up(last.VirtualAddress + last.VirtualSize, dkii_pe.nt.OptionalHeader.SectionAlignment)
  assert dkii_pe.nt.OptionalHeader.SizeOfImage == sections_virt_end
  sections_file_end = my_pe.align_up(last.PointerToRawData + last.SizeOfRawData, dkii_pe.nt.OptionalHeader.FileAlignment)
  assert dkii_pe.size == sections_file_end
  # print(f'{sections_file_end:08X} {len(dkii_data):08X}')

  # assert sections has same alignment
  assert dkii_pe.nt.OptionalHeader.SectionAlignment == flame_pe.nt.OptionalHeader.SectionAlignment
  assert dkii_pe.nt.OptionalHeader.FileAlignment == flame_pe.nt.OptionalHeader.FileAlignment
  delta_virt = sections_virt_end - flame_pe['.text'].VirtualAddress
  delta_file = sections_file_end - flame_pe['.text'].PointerToRawData
  flame_data_start = flame_pe.base + flame_pe['.text'].PointerToRawData
  flame_data_size = (flame_pe['.data'].PointerToRawData + flame_pe['.data'].SizeOfRawData) - flame_pe['.text'].PointerToRawData

  free_sections_left = (dkii_pe.nt.OptionalHeader.SizeOfHeaders - (dkii_pe.sections_end - dkii_pe.base)) / ctypes.sizeof(pe_types.IMAGE_SECTION_HEADER)
  assert free_sections_left >= 4.0
  sections: list[pe_types.IMAGE_SECTION_HEADER] = ctypes.pointer(pe_types.IMAGE_SECTION_HEADER.from_address(dkii_pe.sections_end))
  Name_ty = (ctypes.c_ubyte*8)

  # add flame section headers to dkii and remap them
  def convert_sec(sec: pe_types.IMAGE_SECTION_HEADER, src: pe_types.IMAGE_SECTION_HEADER, name: bytes):
    ctypes.pointer(sec)[0] = src
    sec.Name = Name_ty(*name)
    sec.VirtualAddress += delta_virt
    sec.PointerToRawData += delta_file
  convert_sec(sections[0], flame_pe['.text'], b'.flame_x')
  convert_sec(sections[1], flame_pe['.rdata'], b'.flame_r')
  convert_sec(sections[2], flame_pe['.data'], b'.flame_w')
  dkii_pe.nt.FileHeader.NumberOfSections += 3

  sections: list[pe_types.IMAGE_SECTION_HEADER] = ctypes.pointer(pe_types.IMAGE_SECTION_HEADER.from_address(dkii_pe.sections_end))
  sections[0].Name = Name_ty(*b'.imports')
  last_sec = sections[-1]
  sections[0].PointerToRawData = my_pe.align_up(last_sec.PointerToRawData + last_sec.SizeOfRawData, dkii_pe.nt.OptionalHeader.FileAlignment)
  sections[0].VirtualAddress = my_pe.align_up(last_sec.VirtualAddress + last_sec.VirtualSize, dkii_pe.nt.OptionalHeader.SectionAlignment)
  sections[0].Characteristics = pe_types.IMAGE_SCN_MEM_READ | pe_types.IMAGE_SCN_CNT_INITIALIZED_DATA
  dkii_pe.nt.FileHeader.NumberOfSections += 1

  dkii_pe.nt.OptionalHeader.SizeOfCode += flame_pe.nt.OptionalHeader.SizeOfCode
  dkii_pe.nt.OptionalHeader.SizeOfInitializedData += flame_pe.nt.OptionalHeader.SizeOfInitializedData
  dkii_pe.nt.OptionalHeader.SizeOfUninitializedData += flame_pe.nt.OptionalHeader.SizeOfUninitializedData
  dkii_pe.nt.OptionalHeader.AddressOfEntryPoint = flame_pe.nt.OptionalHeader.AddressOfEntryPoint + delta_virt

  # relocate flame references
  for ty, rva in flame_pe.relocs():
    assert ty is pe_types.IMAGE_REL_BASED.HIGHLOW
    offs = flame_pe.rva2raw(rva)
    src_val = wintypes.DWORD.from_address(flame_pe.base + offs)
    dst_va = src_val.value
    dst_rva = dst_va - flame_pe.nt.OptionalHeader.ImageBase
    dst_rva += delta_virt
    src_val.value = dst_rva + dkii_pe.nt.OptionalHeader.ImageBase
    # print(f'{rva:08X}->{dst_rva:08X} {ty.name}')

    # ctypes.pointer(ctypes.c_char.from_address(flame_pe.base + flame_pe.rva2raw(names[i])))

  # for name, rva in flame_pe.exports():
  #   print(f'{rva + delta_virt:08X} {name}')

  # merge imports
  imports = {}
  for imp in flame_pe.imports():
    if imp.name == 'DKII.dll':
      continue
    # print(imp.name)
    for rva, ord, name, thunk_rva in imp.thunks():
      # print(f' {rva:08X} {ord} {name} {imp.desc.Name + delta_virt:08X} {thunk_rva + delta_virt:08X}')
      imports[f'{imp.name.lower()}:{name if name is not None else ord}'] = (imp.desc.Name + delta_virt, imp.name, name, ord, thunk_rva + delta_virt)
  for imp in dkii_pe.imports():
    # print(imp.name)
    for rva, ord, name, thunk_rva in imp.thunks():
      # print(f' {rva:08X} {ord} {name}')
      imports[f'{imp.name.lower()}:{name if name is not None else ord}'] = (imp.desc.Name, imp.name, name, ord, thunk_rva)
  by_lib: dict[str, ImportTableBuild] = {}
  for dll_name_rva, dll_name, fun_name, ord, thunk_rva in imports.values():
    by_lib.setdefault(
      dll_name.lower(), ImportTableBuild(dll_name_rva, dll_name)
    ).funs.append((fun_name, ord, thunk_rva))
  descriptors = (pe_types.IMAGE_IMPORT_DESCRIPTOR * (len(by_lib) + 1))()
  iat_size = 0
  all_thunks = []
  for i, itb in enumerate(by_lib.values()):
    desc: pe_types.IMAGE_IMPORT_DESCRIPTOR = descriptors[i]
    desc.Name = itb.dll_name_rva
    # print(dll_name)
    itb.thunks = (wintypes.DWORD * (len(itb.funs) + 1))()
    all_thunks.append(itb.thunks)
    for j, (fun_name, ord, thunk_rva) in enumerate(itb.funs):
      if thunk_rva is not None:
        itb.thunks[j] = thunk_rva
      else:
        itb.thunks[j] = ord | pe_types.IMAGE_ORDINAL_FLAG
      # print(f' {ord} {fun_name}')
    iat_size += ctypes.sizeof(itb.thunks)
  iat_rva = dkii_pe['.imports'].VirtualAddress
  descriptors_rva = iat_rva + iat_size
  oiat_rva = descriptors_rva + ctypes.sizeof(descriptors)
  cur_iat_rva = iat_rva
  cur_oiat_rva = oiat_rva
  for i, itb in enumerate(by_lib.values()):
    desc: pe_types.IMAGE_IMPORT_DESCRIPTOR = descriptors[i]
    desc.FirstThunk = cur_iat_rva
    cur_iat_rva += ctypes.sizeof(itb.thunks)
    desc.OriginalFirstThunk = cur_oiat_rva
    cur_oiat_rva += ctypes.sizeof(itb.thunks)
    # print(f'{desc.FirstThunk:08X} {desc.OriginalFirstThunk:08X} {imports_rva:08X} {dll_name}')
  with io.BytesIO() as f:
    for thunks in all_thunks:
      f.write(thunks)
    f.write(descriptors)
    for thunks in all_thunks:
      f.write(thunks)
    imports_data = f.getvalue()
  dkii_pe['.imports'].VirtualSize = len(imports_data)
  dkii_pe['.imports'].SizeOfRawData = my_pe.align_up(len(imports_data), dkii_pe.nt.OptionalHeader.FileAlignment)
  import_data_dir: pe_types.IMAGE_DATA_DIRECTORY = dkii_pe.nt.OptionalHeader.DataDirectory[pe_types.IMAGE_DIRECTORY_ENTRY.IMPORT]
  import_data_dir.VirtualAddress = descriptors_rva
  import_data_dir.Size = ctypes.sizeof(descriptors)
  iat_dir: pe_types.IMAGE_DATA_DIRECTORY = dkii_pe.nt.OptionalHeader.DataDirectory[pe_types.IMAGE_DIRECTORY_ENTRY.IAT]
  iat_dir.VirtualAddress = iat_rva
  iat_dir.Size = iat_size
  dkii_pe.nt.OptionalHeader.SizeOfImage = my_pe.align_up(
    dkii_pe['.imports'].VirtualAddress + dkii_pe['.imports'].VirtualSize,
    dkii_pe.nt.OptionalHeader.SectionAlignment
  )

  with io.BytesIO() as f:
    f.write((ctypes.c_ubyte * dkii_pe.size).from_address(dkii_pe.base))
    f.write((ctypes.c_ubyte * flame_data_size).from_address(flame_data_start))
    f.write(imports_data + (b'\x00' * (dkii_pe['.imports'].SizeOfRawData - len(imports_data))))
    result_data = f.getvalue()

  return my_pe.MyPe(result_data)


def resize_headers_to_fit_sections(dkii_pe: my_pe.MyPe, sections_planning_to_add: int) -> my_pe.MyPe:
  # dkii_pe.nt.OptionalHeader.SizeOfHeaders
  result_headers_size = (dkii_pe.sections_end - dkii_pe.base) + ctypes.sizeof(pe_types.IMAGE_SECTION_HEADER) * sections_planning_to_add
  if result_headers_size > dkii_pe.nt.OptionalHeader.SizeOfHeaders:
    # expand pe header
    new_SizeOfHeaders = my_pe.align_up(result_headers_size, dkii_pe.nt.OptionalHeader.FileAlignment)
    delta_file = new_SizeOfHeaders - dkii_pe.nt.OptionalHeader.SizeOfHeaders
    print(f"expand dkii.exe headers by 0x{delta_file:X}")

    expand_offs = dkii_pe.sections_end - dkii_pe.base
    headers = (ctypes.c_ubyte * expand_offs).from_address(dkii_pe.base)
    content = (ctypes.c_ubyte * (dkii_pe.size - expand_offs)).from_address(dkii_pe.base + expand_offs)
    for sec in dkii_pe.sections:
      sec.PointerToRawData += delta_file
    dkii_pe.nt.OptionalHeader.SizeOfHeaders += delta_file
    with io.BytesIO() as f:
      f.write(headers)
      f.write(b'\x00' * delta_file)
      f.write(content)
      dkii_data = f.getvalue()
    dkii_pe = my_pe.MyPe(dkii_data)
  return dkii_pe


def unpack_data_jmp(pe: my_pe.MyPe, xrefs_map: dict[int, list[tuple[int, int, str]]], va: int, name: str):
  # unpack jump by data pointer
  xrefs = xrefs_map[va]
  assert len(xrefs) == 1
  va, value, rel_ty = xrefs[0]
  rva = va - pe.nt.OptionalHeader.ImageBase
  jmpff25 = (ctypes.c_ubyte * 2).from_address(pe.base + pe.rva2raw(rva) - 2)
  assert bytes(jmpff25) == b"\xFF\x25"
  print(f'{va:08X} {name}')
  xrefs = xrefs_map[va - 2]  #  require relative references cant risk
  assert xrefs
  return va - 2


def bundle_fpo_map(merged_pe, fpomap_data):
  sections: list[pe_types.IMAGE_SECTION_HEADER] = ctypes.pointer(pe_types.IMAGE_SECTION_HEADER.from_address(merged_pe.sections_end))
  Name_ty = (ctypes.c_ubyte*8)
  sections[0].Name = Name_ty(*b'.fpomap')
  last_sec = sections[-1]
  sections[0].PointerToRawData = my_pe.align_up(last_sec.PointerToRawData + last_sec.SizeOfRawData, merged_pe.nt.OptionalHeader.FileAlignment)
  sections[0].VirtualAddress = my_pe.align_up(last_sec.VirtualAddress + last_sec.VirtualSize, merged_pe.nt.OptionalHeader.SectionAlignment)
  sections[0].Characteristics = pe_types.IMAGE_SCN_MEM_READ | pe_types.IMAGE_SCN_CNT_INITIALIZED_DATA
  merged_pe.nt.FileHeader.NumberOfSections += 1

  merged_pe['.fpomap'].VirtualSize = len(fpomap_data)
  merged_pe['.fpomap'].SizeOfRawData = my_pe.align_up(len(fpomap_data), merged_pe.nt.OptionalHeader.FileAlignment)

  merged_pe.nt.OptionalHeader.SizeOfImage = my_pe.align_up(
    merged_pe['.fpomap'].VirtualAddress + merged_pe['.fpomap'].VirtualSize,
    merged_pe.nt.OptionalHeader.SectionAlignment
  )

  with io.BytesIO() as f:
    f.write((ctypes.c_ubyte * merged_pe.size).from_address(merged_pe.base))
    f.write(fpomap_data + (b'\x00' * (merged_pe['.fpomap'].SizeOfRawData - len(fpomap_data))))
    result_data = f.getvalue()

  return my_pe.MyPe(result_data)


def main(
    # dkii
    dkii_exe: pathlib.Path,
    dkii_symmap_file: pathlib.Path,
    dkii_refmap_file: pathlib.Path,
    dkii_espmap_file: pathlib.Path,
    # flame
    flame_exe: pathlib.Path,
    flame_msvcmap_file: pathlib.Path,
    flame_pdb_file: pathlib.Path,
    flame_version: str,
    # out
    output_exe: pathlib.Path,
):
  with open(dkii_exe, 'rb') as f:
    _data = f.read()
  dkii_pe = my_pe.MyPe(_data)

  with open(flame_exe, 'rb') as f:
    _data = f.read()
  flame_pe = my_pe.MyPe(_data)

  # int: pe_types.IMAGE_DATA_DIRECTORY = dkii_pe.nt.OptionalHeader.DataDirectory[pe_types.IMAGE_DIRECTORY_ENTRY.IMPORT]
  # int_start = dkii_pe.base + dkii_pe.rva2raw(int.VirtualAddress)
  # int_hex = bytes((ctypes.c_ubyte * int.Size).from_address(int_start)).hex(' ')
  # while int_hex:
  #   print(int_hex[:16*3])
  #   int_hex = int_hex[16*3:]
  #
  # iat: pe_types.IMAGE_DATA_DIRECTORY = dkii_pe.nt.OptionalHeader.DataDirectory[pe_types.IMAGE_DIRECTORY_ENTRY.IAT]
  # iat_start = dkii_pe.base + dkii_pe.rva2raw(iat.VirtualAddress)
  # iat_hex = bytes((ctypes.c_ubyte * iat.Size).from_address(iat_start)).hex(' ')
  # while iat_hex:
  #   print(iat_hex[:16*3])
  #   iat_hex = iat_hex[16*3:]

  # for sec in flame_pe.sections:
  #   sec_name = bytes(sec.Name).rstrip(b'\x00').decode('ascii')
  #   print(f'{sec.PointerToRawData:08X}-{sec.PointerToRawData + sec.SizeOfRawData:08X} {sec.VirtualAddress:08X}-{sec.VirtualAddress + sec.VirtualSize:08X} {sec_name}')
  # for sec in dkii_pe.sections:
  #   sec_name = bytes(sec.Name).rstrip(b'\x00').decode('ascii')
  #   print(f'{sec.PointerToRawData:08X}-{sec.PointerToRawData + sec.SizeOfRawData:08X} {sec.VirtualAddress:08X}-{sec.VirtualAddress + sec.VirtualSize:08X} {sec_name}')

  dkii_pe = resize_headers_to_fit_sections(dkii_pe, 5)  # x w r imports fpomap
  # (flame_exe.parent / 'dkii_hdr_expanded.exe').write_bytes(dkii_pe.data)
  merged_pe = append_dll_sections_into_exe(dkii_pe.data, flame_pe.data)  # + imports merge
  # (flame_exe.parent / 'dkii_result.exe').write_bytes(merged_pe.data)

  dkii_xrefs: dict[int, list[tuple[int, int, str]]] = collect_xrefs(dkii_refmap_file)
  flame_xrefs: dict[int, list[tuple[int, int, str]]] = {}
  for ty, rva in flame_pe.relocs():
    assert ty is pe_types.IMAGE_REL_BASED.HIGHLOW
    offs = flame_pe.rva2raw(rva)
    src_val = wintypes.DWORD.from_address(flame_pe.base + offs)
    dst_va = src_val.value
    src_va = flame_pe.nt.OptionalHeader.ImageBase + rva
    flame_xrefs.setdefault(dst_va, []).append((src_va, 0, 'VA32'))

  dkii_map, to_replace = read_symbols(dkii_symmap_file)
  dkii2flame_replace: list[ReplaceRefInfo] = []
  flame_map: dict[str, int] = collect_replace_info(flame_msvcmap_file, to_replace, dkii2flame_replace, flame_pe.nt.OptionalHeader.ImageBase)

  delta_virt = merged_pe['.flame_x'].VirtualAddress - flame_pe['.text'].VirtualAddress

  symbols_map: list[tuple[int, str]] = []
  for name, va in dkii_map.items():
    symbols_map.append((va, name))
  for name, va in flame_map.items():
    symbols_map.append((va - flame_pe.nt.OptionalHeader.ImageBase + delta_virt + merged_pe.nt.OptionalHeader.ImageBase, name))
  symbols_map.sort(key=lambda e: e[0])

  fpomap_data: bytes = my_espmap.build_merged_binary_fpomap(
    dkii_espmap_file, flame_pdb_file, symbols_map,
    delta_virt + merged_pe.nt.OptionalHeader.ImageBase)
  merged_pe = bundle_fpo_map(merged_pe, fpomap_data)

  print("new section mapping:")
  for sec in merged_pe.sections:
    sec_name = bytes(sec.Name).rstrip(b'\x00').decode('ascii')
    print(f'  file:{sec.PointerToRawData:08X}-{sec.PointerToRawData + sec.SizeOfRawData:08X} virt:{sec.VirtualAddress:08X}-{sec.VirtualAddress + sec.VirtualSize:08X} name:{sec_name}')
  print()

  def fill_xrefs(to_replace: list[ReplaceRefInfo], xrefs_map: dict[int, list[tuple[int, int, str]]]):
    for rref in to_replace:
      xrefs = xrefs_map.get(rref.target_va, None)
      if xrefs is None:
        print(f'{rref.target_va:08X} symbol {rref.name} has no xrefs')
        raise Exception()
      rref.target_xrefs = xrefs
  fill_xrefs(dkii2flame_replace, dkii_xrefs)

  merged_imports_map: dict[str, int] = {}
  for imp in merged_pe.imports():
    for rva, ord, name, thunk_rva in imp.thunks():
      str_id = f'{imp.name.lower()}:{name if name is not None else ord}'
      merged_imports_map[str_id] = rva
  flame2merge_replace: list[ReplaceRefInfo] = []
  flame2dkii_replace: list[ReplaceRefInfo] = []
  for imp in flame_pe.imports():
    id_dkii = imp.name == 'DKII.dll'
    for rva, ord, name, thunk_rva in imp.thunks():
      if id_dkii:
        str_id = name
        target_va = flame_pe.nt.OptionalHeader.ImageBase + rva
        # if "@@3" in name:
        #   target_va = unpack_data_jmp(flame_pe, flame_xrefs, target_va, name)
        new_va = dkii_map[name]
        flame2dkii_replace.append(ReplaceRefInfo(str_id, target_va, new_va))
      else:
        str_id = f'{imp.name.lower()}:{name if name is not None else ord}'
        target_va = flame_pe.nt.OptionalHeader.ImageBase + rva
        new_va = merged_pe.nt.OptionalHeader.ImageBase + merged_imports_map[str_id]
        flame2merge_replace.append(ReplaceRefInfo(str_id, target_va, new_va))
  flame2merge_replace.append(ReplaceRefInfo('_fpomap_start', flame_map['__fpomap_start'], merged_pe['.fpomap'].VirtualAddress))
  flame2merge_replace.append(ReplaceRefInfo('_dkii_text_start', flame_map['__dkii_text_start'], merged_pe['.text'].VirtualAddress))
  flame2merge_replace.append(ReplaceRefInfo('_dkii_text_start', flame_map['__dkii_text_end'], merged_pe['cseg'].VirtualAddress + merged_pe['cseg'].VirtualSize))
  flame2merge_replace.append(ReplaceRefInfo('_flame_text_start', flame_map['__flame_text_start'], merged_pe['.flame_x'].VirtualAddress))
  flame2merge_replace.append(ReplaceRefInfo('_flame_text_end', flame_map['__flame_text_end'], merged_pe['.flame_x'].VirtualAddress + merged_pe['.flame_x'].VirtualSize))
  fill_xrefs(flame2merge_replace, flame_xrefs)  # '1004B58C 007FF627'

  dkii2merge_replace: list[ReplaceRefInfo] = []
  for imp in dkii_pe.imports():
    for rva, ord, name, thunk_rva in imp.thunks():
      str_id = f'{imp.name.lower()}:{name if name is not None else ord}'
      new_rva = merged_imports_map[str_id]
      dkii2merge_replace.append(ReplaceRefInfo(
        str_id,
        dkii_pe.nt.OptionalHeader.ImageBase + rva,
        merged_pe.nt.OptionalHeader.ImageBase + new_rva
      ))
  fill_xrefs(dkii2merge_replace, dkii_xrefs)

  version_va = flame_map['_Flame_version']
  version_rva = version_va - flame_pe.nt.OptionalHeader.ImageBase + delta_virt
  offs = merged_pe.rva2raw(version_rva)
  version_val = (ctypes.c_char * 64).from_address(merged_pe.base + offs)
  print(f'version: {flame_version}')
  pos = flame_version.find('build')
  if pos != -1:
    flame_version = ' V' + flame_version[:pos - 1] + '\n ' + flame_version[pos:]
  version_val.value = flame_version.encode('ascii')

  for replace_ref in dkii2flame_replace:
    dst_rva = replace_ref.new_va - flame_pe.nt.OptionalHeader.ImageBase + delta_virt
    for dkii_va, value, rel_ty in replace_ref.target_xrefs:
      src_rva = dkii_va - dkii_pe.nt.OptionalHeader.ImageBase
      offs = merged_pe.rva2raw(src_rva)
      src_val = wintypes.DWORD.from_address(merged_pe.base + offs)
      if rel_ty == 'VA32':
        src_val.value = dst_rva + merged_pe.nt.OptionalHeader.ImageBase
      elif rel_ty == 'REL32':
        src_val.value = dst_rva - (src_rva + 4)

  for replace_ref in flame2merge_replace:  # imports
    dst_rva = replace_ref.new_va - merged_pe.nt.OptionalHeader.ImageBase
    for flame_va, value, rel_ty in replace_ref.target_xrefs:
      src_rva = flame_va - flame_pe.nt.OptionalHeader.ImageBase + delta_virt
      offs = merged_pe.rva2raw(src_rva)
      src_val = wintypes.DWORD.from_address(merged_pe.base + offs)
      assert rel_ty == 'VA32'
      src_val.value = dst_rva + merged_pe.nt.OptionalHeader.ImageBase

  for replace_ref in dkii2merge_replace:  # imports
    dst_rva = replace_ref.new_va - merged_pe.nt.OptionalHeader.ImageBase
    for dkii_va, value, rel_ty in replace_ref.target_xrefs:
      src_rva = dkii_va - dkii_pe.nt.OptionalHeader.ImageBase
      offs = merged_pe.rva2raw(src_rva)
      src_val = wintypes.DWORD.from_address(merged_pe.base + offs)
      assert rel_ty == 'VA32'
      src_val.value = dst_rva + merged_pe.nt.OptionalHeader.ImageBase

  for replace_ref in flame2dkii_replace:
    dst_rva = replace_ref.new_va - merged_pe.nt.OptionalHeader.ImageBase
    src_rva = replace_ref.target_va - flame_pe.nt.OptionalHeader.ImageBase + delta_virt
    offs = merged_pe.rva2raw(src_rva)
    src_val = wintypes.DWORD.from_address(merged_pe.base + offs)
    src_val.value = dst_rva + merged_pe.nt.OptionalHeader.ImageBase

  merged_pe.nt.OptionalHeader.Subsystem = pe_types.IMAGE_SUBSYSTEM_WINDOWS_CUI

  output_exe.write_bytes(merged_pe.data)
  with open(output_exe.parent / f'{os.path.splitext(output_exe.name)[0]}.map', 'w') as f:
    for va, name in symbols_map:
      f.write(f'{va:08X} {name}\n')


def start():
  parser = argparse.ArgumentParser(description='Optional app description')
  # dkii
  parser.add_argument('-dkii_exe', type=str, required=True)
  parser.add_argument('-dkii_symmap_file', type=str, required=True)
  parser.add_argument('-dkii_refmap_file', type=str, required=True)
  parser.add_argument('-dkii_espmap_file', type=str, required=True)
  # flame
  parser.add_argument('-flame_exe', type=str, required=True)
  parser.add_argument('-flame_msvcmap_file', type=str, required=True)
  parser.add_argument('-flame_pdb_file', type=str, required=True)
  parser.add_argument('-flame_version', type=str, required=True)
  # out
  parser.add_argument('-output_exe', type=str, required=True)
  args = parser.parse_args()
  print(' '.join(sys.argv))
  main(
    # dkii
    pathlib.Path(args.dkii_exe),
    pathlib.Path(args.dkii_symmap_file),
    pathlib.Path(args.dkii_refmap_file),
    pathlib.Path(args.dkii_espmap_file),
    # flame
    pathlib.Path(args.flame_exe),
    pathlib.Path(args.flame_msvcmap_file),
    pathlib.Path(args.flame_pdb_file),
    args.flame_version,
    # out
    pathlib.Path(args.output_exe)
  )


if __name__ == '__main__':
  start()
