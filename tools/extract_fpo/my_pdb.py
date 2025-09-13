import enum
import functools
import ctypes
import pathlib
import typing
from ctypes import wintypes
import pdb_types


def get_num_pages(length, page_size):
  return (length + page_size - 1) // page_size




class MyBytes:

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


class MyStream:

  def __init__(self, pos: int):
    self.pos = pos

  # def read(self, ty: ctypes.CData) -> ctypes.CData:
  def read(self, ty: ctypes) -> ctypes:
    val = ty.from_address(self.pos)
    self.pos += ctypes.sizeof(ty)
    return val

  def read_indexes(self, size: int, block_size: int) -> list[int]:
    # block_size = self.header.BlockSize
    num_pages = get_num_pages(size, block_size)
    return list(self.read(ctypes.c_uint32 * num_pages))

  def read_str(self) -> str:
    s = ctypes.pointer(ctypes.c_char.from_address(self.pos))
    i = 0
    out = b''
    while True:
      ch = s[i]
      i += 1
      if ch == b'\x00':
        break
      out += ch
    self.pos += i
    return out.decode('ascii')

  def align(self, base: int, align: int):
    assert base <= self.pos
    offs = self.pos - base
    mod = offs % align
    if mod == 0:
      return
    self.pos += align - mod


class MyRootStream(MyBytes):

  def __init__(self, pdb, data: bytes):
    self.pdb = pdb
    super().__init__(data)
    stream = MyStream(self.base)
    num_streams = stream.read(ctypes.c_uint32).value
    stream_sizes = list(stream.read(ctypes.c_uint32 * num_streams))
    block_size = pdb.header.BlockSize
    self.streams = {}
    for stream_idx, size in enumerate(stream_sizes):
      if size == 0xFFFFFFFF:
        continue
      if size == 0:
        continue
      assert size < pdb.size
      indexes = stream.read_indexes(size, block_size)
      for page_idx in indexes:
        assert page_idx < pdb.header.NumBlocks
      self.streams[stream_idx] = (size, indexes)
    assert len(self.data) == (stream.pos - self.base)

  def __getitem__(self, item: int) -> bytes:
    pair = self.streams.get(item)
    if pair is None:
      return None
    size, indexes = pair
    return self.pdb.read_stream_data(indexes)[:size]


class BitSet:

  def __init__(self, stream: MyStream):
    self.sz = stream.read(ctypes.c_uint32).value
    self.words = list(stream.read(ctypes.c_uint32 * self.sz))

  def is_set(self, index):
    word = index // 32
    if word >= self.sz:
      return False
    bit = 1 << (index % 32)
    return (self.words[word] & bit) != 0


class MyPdbInfoStream(MyBytes):

  def __init__(self, pdb, data: bytes):
    self.pdb: MyPdb = pdb
    super().__init__(data)
    stream = MyStream(self.base)
    self.header: pdb_types.PDBInfo = stream.read(pdb_types.PDBInfo)

    # Names
    names_pos = stream.pos
    stream.pos += self.header.cbNames

    cnt = stream.read(ctypes.c_uint32).value
    max = stream.read(ctypes.c_uint32).value
    present = BitSet(stream)
    deleted = BitSet(stream)

    self.present: dict[str, int] = {}
    j = 0
    for i in range(max):
      if present.is_set(i):
        ns = stream.read(ctypes.c_uint32).value
        ni = stream.read(ctypes.c_uint32).value
        name = MyStream(names_pos + ns).read_str()
        assert name not in self.present
        self.present[name] = ni
        self.pdb._stream_names[ni] = name
        j += 1
    assert cnt == j
    unknown1 = stream.read(ctypes.c_uint32).value
    assert unknown1 == 0
    end = self.base + self.size
    self.features = []
    while stream.pos < end:
      self.features.append(stream.read(ctypes.c_uint32).value)
    assert stream.pos == end

  def __getitem__(self, item: str) -> bytes:
    page_num = self.present.get(item)
    return self.pdb.root[page_num]


class ModInfo:

  def __init__(self, stream: MyStream):
    self.header: pdb_types.ModuleInfoHeader = stream.read(pdb_types.ModuleInfoHeader)
    self.modName = stream.read_str()
    self.objName = stream.read_str()

  def parse_symbols(self, pdb):
    pdb: MyPdb = pdb
    if self.header.ModuleSymStream <= 0:
      return
    # parsing .debug$S aka $$SYMBOLS COFF section
    # https://github.com/mfichman/jogo/blob/master/notes/CodeView8.txt
    my_bytes = MyBytes(pdb.root[self.header.ModuleSymStream])
    stream = MyStream(my_bytes.base)
    fin = stream.pos + my_bytes.size
    version = stream.read(ctypes.c_uint32).value
    assert version == 4  # DEBUG_SECTION_MAGIC
    while stream.pos < fin:
      size = stream.read(ctypes.c_uint16).value
      if size == 0:
        break
      end = stream.pos + size
      type = stream.read(ctypes.c_uint16).value
      if type == 0x1101:  # Name of object file
        signature = stream.read(ctypes.c_uint32).value
        name = stream.read_str()
        print(f' {signature:08X} {name}')
      # elif type == 0x113C:
      #   print(bytes(stream.read(ctypes.c_ubyte * (end - stream.pos))))
      #   stream.pos = end
      else:
        data = bytes(stream.read(ctypes.c_ubyte * (end - stream.pos)))
        print(f'unk type {type:04X} {data}')
      stream.align(my_bytes.base, 4)
      assert stream.pos == end
    assert stream.pos < fin
    assert stream.pos > fin - 4


class SectionContrib:

  def __init__(self, stream: MyStream, end):
    self.Version = stream.read(ctypes.c_uint32).value
    # assert self.Version == (0xeffe0000 + 20140516)  # DbiSecContribV2
    assert self.Version == (0xeffe0000 + 19970605)  # DbiSecContribVer60
    self.sections: list[pdb_types.SectionContrib] = []
    while stream.pos < end:
      sec: pdb_types.SectionContrib = stream.read(pdb_types.SectionContrib)
      self.sections.append(sec)
    assert stream.pos == end


class SectionMap:

  def __init__(self, stream: MyStream, end):
    self.Count = stream.read(ctypes.c_uint16).value
    self.LogCount = stream.read(ctypes.c_uint16).value
    self.sections: list[pdb_types.SecMapEntry] = []
    for i in range(self.Count):
      entry: pdb_types.SecMapEntry = stream.read(pdb_types.SecMapEntry)
      self.sections.append(entry)
    assert stream.pos == end


class MyPdbDebugStream(MyBytes):

  def __init__(self, pdb, data: bytes):
    self.pdb: MyPdb = pdb
    super().__init__(data)
    stream = MyStream(self.base)
    self.header: pdb_types.DBIHeader = stream.read(pdb_types.DBIHeader)
    self.pdb._stream_names[self.header.GlobalSymbolStreamIndex] = f'GlobalSymbolStreamIndex'
    self.pdb._stream_names[self.header.pssymStream] = f'PublicSymbolStreamIndex'
    self.pdb._stream_names[self.header.symrecStream] = f'SymRecordStreamIndex'

    self.ModInfos: list[ModInfo] = []
    dbiexhdr_end = stream.pos + self.header.module_size - ctypes.sizeof(pdb_types.ModuleInfoHeader)
    while stream.pos < dbiexhdr_end:
      info = ModInfo(stream)
      # info.parse_symbols(pdb)
      if info.header.ModuleSymStream > 0:  # .debug$S aka $$SYMBOLS
        self.pdb._stream_names[info.header.ModuleSymStream] = f'ModuleSymStream_{pathlib.Path(info.modName).name}'
      self.ModInfos.append(info)
      stream.align(self.base, 4)

    # "Section Contribution"
    self.SectionContrib = SectionContrib(stream, stream.pos + self.header.secconSize)

    # "Section Map"
    self.SectionMap = SectionMap(stream, stream.pos + self.header.secmapSize)
    # for sec in self.SectionMap.sections:
    #   print(f'offs={sec.Offset:08X} sz={sec.SecByteLength:<6X} fl={sec.Flags:08X} ovl={sec.Ovl:X} gr={sec.Group:X} frame={sec.Frame:X}'
    #         f' sec_name={sec.SecName:X} cls_name={sec.ClassName:X}')

    #
    # see: http://pierrelib.pagesperso-orange.fr/exec_formats/MS_Symbol_Type_v1.0.pdf
    # the contents of the filinfSize section is a 'sstFileIndex'
    #
    # "File Info"
    file_info_end = stream.pos + self.header.filinfSize
    # fileIndex: pdb_types.SstFileIndex = stream.read(pdb_types.SstFileIndex)
    # modStart = list(stream.read(wintypes.WORD * fileIndex.cMod))  # ModiCount,NumModules
    # cRefCnt = list(stream.read(wintypes.WORD * fileIndex.cMod))  # FileCount,NumSourceFiles
    # NameRef = list(stream.read(wintypes.DWORD * fileIndex.cRef))  # Mod Indices
    # self.modules = []  # array of arrays of files
    # self.files = []  # array of files (non unique)
    # namesPos = stream.pos
    # # Names = stream.read(end - stream.pos)
    # for i in range(0, fileIndex.cMod):
    #   these = []
    #   for j in range(modStart[i], modStart[i] + cRefCnt[i]):
    #     ms = MyStream(namesPos + NameRef[j])
    #     name = ms.read_str()
    #     self.files.append(name)
    #     these.append(name)
    #   self.modules.append(these)
    stream.pos = file_info_end

    # "TSM - type server map"  related somehow to the usage of /Zi and mspdbsrv.exe.
    stream.pos += self.header.tsmapSize  # TypeServerSize

    # "EC" - Edit & Continue support in MSVC
    stream.pos += self.header.ecinfoSize  # ECSubstreamSize

    # The data we really want
    self.DBIDbgHeader: pdb_types.DbiDbgHeader = stream.read(pdb_types.DbiDbgHeader)
    assert (stream.pos - self.base) <= self.size
    assert (stream.pos - self.base) > self.size - 4

    for name in ['snFPO', 'snException', 'snFixup', 'snOmapToSrc', 'snOmapFromSrc', 'snSectionHdr', 'snTokenRidMap', 'snXdata', 'snPdata', 'snNewFPO', 'snSectionHdrOrig']:
      sn = getattr(self.DBIDbgHeader, name)
      if sn != -1:
        self.pdb._stream_names[sn] = name[2:]


class FrameType(enum.IntEnum):
  Fpo = 0
  Trap = 1
  Tss = 2
  NonFpo = 3  # Standard
  FrameData = 4


class FrameData:

  def __init__(self, ty, code_start, code_size, locals_size, params_size, prolog_size, saved_regs_size,
               max_stack_size, has_structured_eh, has_cpp_eh, is_function_start, uses_base_pointer, program):
    # Compiler-specific frame type.
    self.ty: FrameType = ty

    # A Relative Virtual Address in an unoptimized PE file.
    #
    # An internal RVA points into the PDB internal address space and may not correspond to RVAs of the
    # executable. It can be converted into an actual [`Rva`] suitable for debugging purposes using
    # [`to_rva`](Self::to_rva).

    # Relative virtual address of the start of the code block.
    #
    # Note that this address is internal to the PDB. To convert this to an actual [`Rva`], use
    # [`PdbInternalRva::to_rva`].
    self.code_start: int = code_start  # PdbInternalRva

    # Size of the code block covered by this frame data in bytes.
    self.code_size: int = code_size

    # Size of local variables pushed on the stack in bytes.
    self.locals_size: int = locals_size

    # Size of parameters pushed on the stack in bytes.
    self.params_size: int = params_size

    # Number of bytes of prologue code in the block.
    self.prolog_size: int = prolog_size

    # Size of saved registers pushed on the stack in bytes.
    self.saved_regs_size: int = saved_regs_size

    # The maximum number of bytes pushed on the stack.
    self.max_stack_size: int or None = max_stack_size

    # Indicates that structured exception handling is in effect.
    self.has_structured_eh: bool = has_structured_eh

    # Indicates that C++ exception handling is in effect.
    self.has_cpp_eh: bool = has_cpp_eh

    # Indicates that this frame is the start of a function.
    self.is_function_start: bool = is_function_start

    # Indicates that this function uses the EBP register.
    self.uses_base_pointer: bool = uses_base_pointer

    # A program string allowing to reconstruct register values for this frame.
    #
    # The program string is a sequence of macros that is interpreted in order to establish the
    # prologue. For example, a typical stack frame might use the program string `"$T0 $ebp = $eip
    # $T0 4 + ^ = $ebp $T0 ^ = $esp $T0 8 + ="`. The format is reverse polish notation, where the
    # operators follow the operands. `T0` represents a temporary variable on the stack.
    #
    # Note that the program string is specific to the CPU and to the calling convention set up for
    # the function represented by the current stack frame.
    self.program: str or None = program


class MyPdbFPOStream(MyBytes):

  def __init__(self, pdb, data: bytes):
    self.pdb = pdb
    super().__init__(data)
    stream = MyStream(self.base)

    self.fpos: list[FrameData] = []
    end = self.base + self.size
    while stream.pos < end:
      fpo: pdb_types.FPO_DATA = stream.read(pdb_types.FPO_DATA)
      self.fpos.append(FrameData(
        ty=FrameType(fpo.Attributes >> 14),
        code_start=fpo.ulOffStart,
        code_size=fpo.cbProcSize,
        prolog_size=fpo.Attributes & 0xF,
        locals_size=fpo.cdwLocals * 4,
        params_size=fpo.cdwParams * 4,
        saved_regs_size=((fpo.Attributes >> 8) & 0x7) * 4,
        max_stack_size=None,
        has_structured_eh=(fpo.Attributes >> 9) & 1 != 0,
        has_cpp_eh=False,
        is_function_start=False,
        uses_base_pointer=(fpo.Attributes >> 10) & 1 != 0,
        program=None
      ))
    assert (stream.pos - self.base) == self.size


class MyPdbNewFPOStream(MyBytes):

  def __init__(self, pdb, data: bytes):
    self.pdb: MyPdb = pdb
    super().__init__(data)
    stream = MyStream(self.base)

    self.fpos: list[FrameData] = []
    end = self.base + self.size
    while stream.pos < end:
      fpo: pdb_types.FPO_DATA_V2 = stream.read(pdb_types.FPO_DATA_V2)
      prog_string = MyStream(self.pdb.names.names_start + fpo.ProgramStringOffset).read_str()
      self.fpos.append(FrameData(
        ty=FrameType.FrameData,
        code_start=fpo.ulOffStart,
        code_size=fpo.cbProcSize,
        prolog_size=fpo.cbProlog,
        locals_size=fpo.cbLocals,
        params_size=fpo.cbParams,
        saved_regs_size=fpo.cbSavedRegs,
        max_stack_size=fpo.maxStack,
        has_structured_eh=fpo.flags & 1 != 0,
        has_cpp_eh=fpo.flags & 2 != 0,
        is_function_start=fpo.flags & 4 != 0,
        uses_base_pointer=False,
        program=prog_string,
      ))
    assert (stream.pos - self.base) == self.size


class MyPdbNamesStream(MyBytes):

  def __init__(self, pdb, data: bytes):
    self.pdb: MyPdb = pdb
    super().__init__(data)
    stream = MyStream(self.base)

    self.header = stream.read(pdb_types.PDBStringTableHeader)
    self.names_start = stream.pos


class MySectionHeadersStream(MyBytes):

  def __init__(self, pdb, data: bytes):
    self.pdb: MyPdb = pdb
    super().__init__(data)
    stream = MyStream(self.base)

    end = self.base + self.size
    self.sections: list[pdb_types.IMAGE_SECTION_HEADER] = []
    while stream.pos < end:
      self.sections.append(stream.read(pdb_types.IMAGE_SECTION_HEADER))
    assert stream.pos == end
    # for sec in self.sections:
    #   name = bytes(sec.Name).rstrip(b'\x00').decode('ascii')
    #   print(f'{name:<8}'
    #         f' vir={sec.VirtualAddress:08X} {sec.VirtualSize:08X}'
    #         f' raw={sec.PointerToRawData:08X} {sec.SizeOfRawData:08X}'
    #         f' {sec.PointerToRelocations:08X} {sec.PointerToLinenumbers:08X}'
    #         f' {sec.NumberOfRelocations} {sec.NumberOfLinenumbers}'
    #         f' chars={sec.Characteristics:08X}')


class MyPdb(MyBytes):

  def __init__(self, data: bytes):
    super().__init__(data)
    magic = bytes((ctypes.c_ubyte * 0x20).from_address(self.base))
    assert magic == b"Microsoft C/C++ MSF 7.00\r\n\x1A\x44\x53\x00\x00\x00"

    indexes_size = get_num_pages(self.header.RootStreamSize, self.header.BlockSize) * 4
    root_indexes_stream = MyBytes(self.read_stream_data(MyStream(self.base + 0x20 + ctypes.sizeof(pdb_types.SuperBlock)).read_indexes(indexes_size, self.header.BlockSize)))
    root_stream = self.read_stream_data(MyStream(root_indexes_stream.base).read_indexes(self.header.RootStreamSize, self.header.BlockSize))
    self.root = MyRootStream(self, root_stream[:self.header.RootStreamSize])
    self._stream_names = {0: 'prev_root', 1: 'pdb_info', 2: 'tpi', 3: 'dbi', 4: 'ipi'}

    # probably contains changed pages from previous linking. maybe you can recover all the pdb streams from previous linking
    self.prev_root_delta = MyRootStream(self, self.root[0])
    self.pdb_info = MyPdbInfoStream(self, self.root[1])

    # udt_src_line_undone: bytes = self.pdb_info['/UDTSRCLINEUNDONE']
    # header_block: bytes = self.pdb_info['/src/headerblock']
    # link_info: bytes = self.pdb_info['/LinkInfo']
    # tm_cache: bytes = self.pdb_info['/TMCache']
    self.names = MyPdbNamesStream(self, self.pdb_info['/names'])
    # source_link: bytes = self.pdb_info['sourcelink$1']

    print(self.pdb_info.present)
    self.debug = MyPdbDebugStream(self, self.root[3])  # DBI Stream

    # symbol_records = MyBytes(self.root[self.debug.header.symrecStream])
    # stream = MyStream(symbol_records.base)

    self.fpo = MyPdbFPOStream(self, self.root[self.debug.DBIDbgHeader.snFPO])  # .debug$F
    self.new_fpo = MyPdbNewFPOStream(self, self.root[self.debug.DBIDbgHeader.snNewFPO])
    self.section_headers = MySectionHeadersStream(self, self.root[self.debug.DBIDbgHeader.snSectionHdr])

  def read_stream_data(self, indexes: list[int]) -> bytes:
    block_size = self.header.BlockSize
    blocks = b''
    for idx in indexes:
      blocks += bytes((ctypes.c_ubyte * block_size).from_address(self.base + idx * block_size))
    return blocks

  @functools.cached_property
  def header(self) -> pdb_types.SuperBlock:
    return pdb_types.SuperBlock.from_address(self.base + 0x20)

