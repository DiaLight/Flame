import functools
import ctypes
import typing
from ctypes import wintypes
import pe_types


def align_up(val, align):
  return (val + align - 1) & ~(align - 1)


class MyImport:

  def __init__(self, pe, desc: pe_types.IMAGE_IMPORT_DESCRIPTOR):
    self.pe: MyPe = pe
    self.desc = desc

  @property
  def name(self):
    return ctypes.string_at(self.pe.base + self.pe.rva2raw(self.desc.Name)).decode('ascii')

  def thunks(self) -> typing.Iterable[typing.Tuple[int, int, str]]:
    start = self.pe.base + self.pe.rva2raw(self.desc.FirstThunk)
    pos = start
    while True:
      val = wintypes.DWORD.from_address(pos).value
      if val == 0:
        break
      if val & pe_types.IMAGE_ORDINAL_FLAG != 0:
        thunk_rva = None
        ord = val & 0xFFFF
        name = None
      else:
        thunk_rva = val
        thunk_pos = self.pe.base + self.pe.rva2raw(val)
        ord = wintypes.WORD.from_address(thunk_pos).value
        name = ctypes.string_at(thunk_pos + 2).decode('ascii')
      rva = self.desc.FirstThunk + (pos - start)
      yield rva, ord, name, thunk_rva
      pos += ctypes.sizeof(wintypes.DWORD)

  def original_thunks(self) -> typing.Iterable[typing.Tuple[int, int, str]]:
    start = self.pe.base + self.pe.rva2raw(self.desc.OriginalFirstThunk)
    pos = start
    while pos[0] != 0:
      val = wintypes.DWORD.from_address(pos).value
      name = None
      if val & pe_types.IMAGE_ORDINAL_FLAG != 0:
        ord = val & 0xFFFF
      else:
        thunk_pos = self.pe.base + self.pe.rva2raw(val)
        ord = wintypes.WORD.from_address(thunk_pos).value
        name = ctypes.string_at(thunk_pos + 2).decode('ascii')
      rva = self.desc.OriginalFirstThunk + (pos - start)
      yield rva, ord, name
      pos += ctypes.sizeof(wintypes.DWORD)


class MyPe:

  def __init__(self, data: bytes):
    self._data = bytearray(data)
    self._c_data = (ctypes.c_char*len(self._data)).from_buffer(self._data)

  @property
  def data(self) -> bytearray:
    return self._data

  @functools.cached_property
  def size(self) -> int:
    return len(self._data)

  @functools.cached_property
  def base(self) -> int:
    return ctypes.addressof(self._c_data)

  @functools.cached_property
  def dos(self) -> pe_types.IMAGE_DOS_HEADER:
    return pe_types.IMAGE_DOS_HEADER.from_address(self.base)

  @functools.cached_property
  def nt(self) -> pe_types.IMAGE_NT_HEADERS32:
    return pe_types.IMAGE_NT_HEADERS32.from_address(self.base + self.dos.e_lfanew)

  @functools.cached_property
  def sections_start(self) -> int:
    return ctypes.addressof(self.nt.OptionalHeader) + self.nt.FileHeader.SizeOfOptionalHeader

  @property
  def sections(self) -> typing.Iterable[pe_types.IMAGE_SECTION_HEADER]:
    sections = ctypes.pointer(pe_types.IMAGE_SECTION_HEADER.from_address(self.sections_start))
    for i in range(self.nt.FileHeader.NumberOfSections):
      yield sections[i]

  def rva2raw(self, rva):
    for sec in self.sections:
      if sec.VirtualAddress <= rva < (sec.VirtualAddress + sec.VirtualSize):
        return rva - sec.VirtualAddress + sec.PointerToRawData
    raise Exception(f'rva {rva:08X} cannot be converted to raw')

  @functools.lru_cache
  def section_by_name(self, name: str) -> pe_types.IMAGE_SECTION_HEADER:
    sections = ctypes.pointer(pe_types.IMAGE_SECTION_HEADER.from_address(self.sections_start))
    for i in range(self.nt.FileHeader.NumberOfSections):
      sec = sections[i]
      sec_name = bytes(sec.Name).rstrip(b'\x00').decode('ascii')
      if sec_name == name:
        return sec
    raise Exception(f'section {name} is not found')

  @functools.lru_cache
  def has_section(self, name: str) -> bool:
    sections = ctypes.pointer(pe_types.IMAGE_SECTION_HEADER.from_address(self.sections_start))
    for i in range(self.nt.FileHeader.NumberOfSections):
      sec = sections[i]
      sec_name = bytes(sec.Name).rstrip(b'\x00').decode('ascii')
      if sec_name == name:
        return True
    return False

  def __getitem__(self, name: str) -> pe_types.IMAGE_SECTION_HEADER:
    return self.section_by_name(name)

  @property
  def sections_end(self) -> int:
    sections = ctypes.pointer(pe_types.IMAGE_SECTION_HEADER.from_address(self.sections_start))
    return ctypes.addressof(sections[self.nt.FileHeader.NumberOfSections])

  def relocs(self) -> typing.Iterable[typing.Tuple[pe_types.IMAGE_REL_BASED, int]]:
    reloc = self.section_by_name('.reloc')
    if reloc.VirtualSize > reloc.SizeOfRawData:
      raise Exception(f'failed {reloc.VirtualSize:08X} <= {reloc.SizeOfRawData:08X}')
    pos = self.base + reloc.PointerToRawData
    relocs_end = pos + reloc.VirtualSize
    while pos < relocs_end:
      rel = pe_types.IMAGE_BASE_RELOCATION.from_address(pos)
      rel_base = rel.VirtualAddress
      block_end = pos + rel.SizeOfBlock
      pos += ctypes.sizeof(pe_types.IMAGE_BASE_RELOCATION)
      while pos < block_end:
        rel_val = wintypes.WORD.from_address(pos).value
        if rel_val:
          rel_ty = rel_val >> 12
          rel_offs = rel_val & 0xFFF
          rel_rva = rel_base + rel_offs
          yield pe_types.IMAGE_REL_BASED(rel_ty), rel_rva
        pos += 2
      pos = align_up(pos, 4)

  def exports(self) -> typing.Iterable[typing.Tuple[str, int]]:
    export_data_dir: pe_types.IMAGE_DATA_DIRECTORY = self.nt.OptionalHeader.DataDirectory[pe_types.IMAGE_DIRECTORY_ENTRY.EXPORT]
    if export_data_dir.VirtualAddress == 0:
      return
    export_dir = pe_types.IMAGE_EXPORT_DIRECTORY.from_address(self.base + self.rva2raw(export_data_dir.VirtualAddress))
    functions = ctypes.pointer(wintypes.DWORD.from_address(self.base + self.rva2raw(export_dir.AddressOfFunctions)))
    names = ctypes.pointer(wintypes.DWORD.from_address(self.base + self.rva2raw(export_dir.AddressOfNames)))
    ordinals = ctypes.pointer(wintypes.WORD.from_address(self.base + self.rva2raw(export_dir.AddressOfNameOrdinals)))
    for i in range(export_dir.NumberOfNames):
      exp_name = ctypes.string_at(self.base + self.rva2raw(names[i])).decode('ascii')
      rva = functions[ordinals[i]]
      yield exp_name, rva

  def imports(self) -> typing.Iterable[MyImport]:
    import_data_dir: pe_types.IMAGE_DATA_DIRECTORY = self.nt.OptionalHeader.DataDirectory[pe_types.IMAGE_DIRECTORY_ENTRY.IMPORT]
    if import_data_dir.VirtualAddress == 0:
      return

    pos = self.base + self.rva2raw(import_data_dir.VirtualAddress)
    while True:
      desc = pe_types.IMAGE_IMPORT_DESCRIPTOR.from_address(pos)
      if desc.Name == 0 and desc.FirstThunk == 0:
        break
      yield MyImport(self, desc)
      pos += ctypes.sizeof(pe_types.IMAGE_IMPORT_DESCRIPTOR)
