import ctypes
import enum
from ctypes import wintypes


class SuperBlock(ctypes.Structure):
  _fields_ = [
    ("BlockSize", wintypes.DWORD),
    ("FreeBlockMapBlock", wintypes.DWORD),
    ("NumBlocks", wintypes.DWORD),
    ("RootStreamSize", wintypes.DWORD),
    ("Reserved", wintypes.DWORD),
  ]
  BlockSize: int
  FreeBlockMapBlock: int
  NumBlocks: int
  RootStreamSize: int
  Reserved: int


class PDBInfo(ctypes.Structure):
  _fields_ = [
    ("Version", wintypes.DWORD),
    ("TimeDateStamp", wintypes.DWORD),
    ("Age", wintypes.DWORD),
    ("GUID", wintypes.BYTE * 16),
    ("cbNames", wintypes.DWORD),
  ]
  Version: int
  TimeDateStamp: int
  Age: int
  GUID: wintypes.BYTE * 16
  cbNames: int


class DBIHeader(ctypes.Structure):
  _fields_ = [
    ("magic", wintypes.DWORD),
    ("version", wintypes.DWORD),
    ("age", wintypes.DWORD),
    ("GlobalSymbolStreamIndex", wintypes.WORD),
    ("vers", wintypes.WORD),
    ("pssymStream", wintypes.WORD),
    ("pdbver", wintypes.WORD),
    ("symrecStream", wintypes.WORD),
    ("pdbver2", wintypes.WORD),
    ("module_size", wintypes.DWORD),
    ("secconSize", wintypes.DWORD),
    ("secmapSize", wintypes.DWORD),
    ("filinfSize", wintypes.DWORD),
    ("tsmapSize", wintypes.DWORD),
    ("mfcIndex", wintypes.DWORD),
    ("dbghdrSize", wintypes.DWORD),
    ("ecinfoSize", wintypes.DWORD),
    ("flags", wintypes.WORD),
    ("Machine", wintypes.WORD),
    ("resvd", wintypes.DWORD),
  ]
  magic: int
  version: int
  age: int
  GlobalSymbolStreamIndex: int  # GlobalSymbolStreamIndex
  vers: int  # BuildNumber
  pssymStream: int  # PublicSymbolStreamIndex
  pdbver: int  # PdbDllVersion
  symrecStream: int  # SymRecordStreamIndex
  pdbver2: int  # PdbDllRbld
  module_size: int  # ModiSubstreamSize
  secconSize: int  # SecContrSubstreamSize
  secmapSize: int  # SectionMapSize
  filinfSize: int  # FileInfoSize
  tsmapSize: int  # TypeServerSize
  mfcIndex: int  # MFCTypeServerIndex
  dbghdrSize: int  # OptionalDbgHdrSize
  ecinfoSize: int  # ECSubstreamSize
  flags: int
  Machine: int  # MachineType
  resvd: int  # Reserved


class SectionContrib(ctypes.Structure):
  _fields_ = [
    ("ISect", wintypes.SHORT),
    ("_pad1", wintypes.WORD),
    ("Off", wintypes.DWORD),
    ("Size", wintypes.LONG),
    ("Characteristics", wintypes.DWORD),
    ("Imod", wintypes.WORD),
    ("_pad2", wintypes.WORD),
    ("DataCrc", wintypes.DWORD),
    ("RelocCrc", wintypes.DWORD),
  ]
  ISect: int
  Off: int
  Size: int
  Characteristics: int
  Imod: int
  DataCrc: int
  RelocCrc: int


class ModuleInfoHeader(ctypes.Structure):
  _fields_ = [
    ("opened", wintypes.SHORT),
    ("_pad1", wintypes.WORD),
    ("range", SectionContrib),  # SectionContr
    ("flags", wintypes.WORD),
    ("ModuleSymStream", wintypes.SHORT),
    ("SymByteSize", wintypes.DWORD),  # SymByteSize
    ("oldLineSize", wintypes.DWORD),  # C11ByteSize
    ("lineSize", wintypes.DWORD),  # C13ByteSize
    ("nSrcFiles", wintypes.WORD),  # SourceFileCount
    ("_pad2", wintypes.WORD),
    ("offsets", wintypes.DWORD),
    ("niSource", wintypes.DWORD),  # SourceFileNameIndex
    ("niCompiler", wintypes.DWORD),  # PdbFilePathNameIndex
  ]
  opened: int
  range: SectionContrib
  flags: int
  ModuleSymStream: int  # llvm: ModDiStream
  SymByteSize: int
  oldLineSize: int  # llvm: C11Bytes
  lineSize: int  # llvm: C13Bytes
  nSrcFiles: int
  offsets: int
  niSource: int
  niCompiler: int


class SstFileIndex(ctypes.Structure):  # llvm: FileInfoSubstreamHeader
  _fields_ = [
    ("num_modules", wintypes.WORD),
    ("num_source_files", wintypes.WORD),
  ]
  num_modules: int
  num_source_files: int


class DbiDbgHeader(ctypes.Structure):
  _fields_ = [
    ("snFPO", wintypes.SHORT),
    ("snException", wintypes.SHORT),
    ("snFixup", wintypes.SHORT),
    ("snOmapToSrc", wintypes.SHORT),
    ("snOmapFromSrc", wintypes.SHORT),
    ("snSectionHdr", wintypes.SHORT),
    ("snTokenRidMap", wintypes.SHORT),
    ("snXdata", wintypes.SHORT),
    ("snPdata", wintypes.SHORT),
    ("snNewFPO", wintypes.SHORT),
    ("snSectionHdrOrig", wintypes.SHORT),
  ]
  snFPO: int
  snException: int
  snFixup: int
  snOmapToSrc: int
  snOmapFromSrc: int
  snSectionHdr: int
  snTokenRidMap: int
  snXdata: int
  snPdata: int
  snNewFPO: int
  snSectionHdrOrig: int


class FPO_DATA(ctypes.Structure):
  _fields_ = [
    ("ulOffStart", wintypes.DWORD),
    ("cbProcSize", wintypes.DWORD),
    ("cdwLocals", wintypes.DWORD),
    ("cdwParams", wintypes.WORD),
    ("Attributes", wintypes.WORD),
  ]
  ulOffStart: int
  cbProcSize: int
  cdwLocals: int
  cdwParams: int
  Attributes: int


class FPO_DATA_V2(ctypes.Structure):
  _fields_ = [
    ("ulOffStart", wintypes.DWORD),  # RvaStart
    ("cbProcSize", wintypes.DWORD),
    ("cbLocals", wintypes.DWORD),
    ("cbParams", wintypes.DWORD),
    ("maxStack", wintypes.DWORD),
    ("ProgramStringOffset", wintypes.DWORD),
    ("cbProlog", wintypes.WORD),
    ("cbSavedRegs", wintypes.WORD),
    ("flags", wintypes.DWORD),
  ]
  ulOffStart: int
  cbProcSize: int
  cbLocals: int
  cbParams: int
  maxStack: int
  ProgramStringOffset: int
  cbProlog: int
  cbSavedRegs: int
  flags: int
  # SEH = 1,
  # CPPEH = 2,  # conjectured
  # fnStart = 4,


class PDBStringTableHeader(ctypes.Structure):
  _fields_ = [
    ("Signature", wintypes.DWORD),
    ("HashVersion", wintypes.DWORD),
    ("ByteSize", wintypes.DWORD),
  ]
  Signature: int
  HashVersion: int
  ByteSize: int


class SecMapEntry(ctypes.Structure):
  _fields_ = [
    ("Flags", wintypes.WORD),
    ("Ovl", wintypes.WORD),
    ("Group", wintypes.WORD),
    ("Frame", wintypes.WORD),
    ("SecName", wintypes.SHORT),
    ("ClassName", wintypes.SHORT),
    ("Offset", wintypes.DWORD),
    ("SecByteLength", wintypes.LONG),
  ]
  Flags: int
  Ovl: int
  Group: int
  Frame: int
  SecName: int
  ClassName: int
  Offset: int
  SecByteLength: int


IMAGE_SIZEOF_SHORT_NAME = 8


class IMAGE_SECTION_HEADER(ctypes.Structure):
  _fields_ = [
    ("Name", wintypes.BYTE * IMAGE_SIZEOF_SHORT_NAME),
    ("VirtualSize", wintypes.DWORD),
    ("VirtualAddress", wintypes.DWORD),
    ("SizeOfRawData", wintypes.DWORD),
    ("PointerToRawData", wintypes.DWORD),
    ("PointerToRelocations", wintypes.DWORD),
    ("PointerToLinenumbers", wintypes.DWORD),
    ("NumberOfRelocations", wintypes.WORD),
    ("NumberOfLinenumbers", wintypes.WORD),
    ("Characteristics", wintypes.DWORD),
  ]
  Name: wintypes.BYTE * IMAGE_SIZEOF_SHORT_NAME
  VirtualSize: int
  VirtualAddress: int
  SizeOfRawData: int
  PointerToRawData: int
  PointerToRelocations: int
  PointerToLinenumbers: int
  NumberOfRelocations: int
  NumberOfLinenumbers: int
  Characteristics: int

  @property
  def name(self):
      return bytes(self.Name).rstrip(b'\x00').decode('ASCII')

  def __repr__(self):
    return f'name:{self.name} virt:{self.VirtualAddress:X}-{self.VirtualAddress + self.VirtualSize:X} raw:{self.PointerToRawData:X}-{self.PointerToRawData + self.SizeOfRawData:X} ch:{self.Characteristics:08X}'


class SymbolType(enum.IntEnum):
  # 16 bit symbol types. Not very useful, provided only for reference.
  S_COMPILE = 0x0001
  S_REGISTER_16t = 0x0002
  S_CONSTANT_16t = 0x0003
  S_UDT_16t = 0x0004
  S_SSEARCH = 0x0005
  S_SKIP = 0x0007
  S_CVRESERVE = 0x0008
  S_OBJNAME_ST = 0x0009
  S_ENDARG = 0x000a
  S_COBOLUDT_16t = 0x000b
  S_MANYREG_16t = 0x000c
  S_RETURN = 0x000d
  S_ENTRYTHIS = 0x000e
  S_BPREL16 = 0x0100
  S_LDATA16 = 0x0101
  S_GDATA16 = 0x0102
  S_PUB16 = 0x0103
  S_LPROC16 = 0x0104
  S_GPROC16 = 0x0105
  S_THUNK16 = 0x0106
  S_BLOCK16 = 0x0107
  S_WITH16 = 0x0108
  S_LABEL16 = 0x0109
  S_CEXMODEL16 = 0x010a
  S_VFTABLE16 = 0x010b
  S_REGREL16 = 0x010c
  S_BPREL32_16t = 0x0200
  S_LDATA32_16t = 0x0201
  S_GDATA32_16t = 0x0202
  S_PUB32_16t = 0x0203
  S_LPROC32_16t = 0x0204
  S_GPROC32_16t = 0x0205
  S_THUNK32_ST = 0x0206
  S_BLOCK32_ST = 0x0207
  S_WITH32_ST = 0x0208
  S_LABEL32_ST = 0x0209
  S_CEXMODEL32 = 0x020a
  S_VFTABLE32_16t = 0x020b
  S_REGREL32_16t = 0x020c
  S_LTHREAD32_16t = 0x020d
  S_GTHREAD32_16t = 0x020e
  S_SLINK32 = 0x020f
  S_LPROCMIPS_16t = 0x0300
  S_GPROCMIPS_16t = 0x0301
  S_PROCREF_ST = 0x0400
  S_DATAREF_ST = 0x0401
  S_ALIGN = 0x0402
  S_LPROCREF_ST = 0x0403
  S_OEM = 0x0404

  # All post 16 bit symbol types have the 0x1000 bit set.
  S_TI16_MAX = 0x1000

  # Mostly unused "start" symbol types.
  S_REGISTER_ST = 0x1001
  S_CONSTANT_ST = 0x1002
  S_UDT_ST = 0x1003
  S_COBOLUDT_ST = 0x1004
  S_MANYREG_ST = 0x1005
  S_BPREL32_ST = 0x1006
  S_LDATA32_ST = 0x1007
  S_GDATA32_ST = 0x1008
  S_PUB32_ST = 0x1009
  S_LPROC32_ST = 0x100a
  S_GPROC32_ST = 0x100b
  S_VFTABLE32 = 0x100c
  S_REGREL32_ST = 0x100d
  S_LTHREAD32_ST = 0x100e
  S_GTHREAD32_ST = 0x100f
  S_LPROCMIPS_ST = 0x1010
  S_GPROCMIPS_ST = 0x1011
  S_COMPILE2_ST = 0x1013
  S_MANYREG2_ST = 0x1014
  S_LPROCIA64_ST = 0x1015
  S_GPROCIA64_ST = 0x1016
  S_LOCALSLOT_ST = 0x1017
  S_PARAMSLOT_ST = 0x1018
  S_GMANPROC_ST = 0x101a
  S_LMANPROC_ST = 0x101b
  S_RESERVED1 = 0x101c
  S_RESERVED2 = 0x101d
  S_RESERVED3 = 0x101e
  S_RESERVED4 = 0x101f
  S_LMANDATA_ST = 0x1020
  S_GMANDATA_ST = 0x1021
  S_MANFRAMEREL_ST = 0x1022
  S_MANREGISTER_ST = 0x1023
  S_MANSLOT_ST = 0x1024
  S_MANMANYREG_ST = 0x1025
  S_MANREGREL_ST = 0x1026
  S_MANMANYREG2_ST = 0x1027
  S_MANTYPREF = 0x1028
  S_UNAMESPACE_ST = 0x1029

  # End of S_*_ST symbols, which do not appear to be generated by modern
  # compilers.
  S_ST_MAX = 0x1100

  S_WITH32 = 0x1104
  S_MANYREG = 0x110a
  S_LPROCMIPS = 0x1114
  S_GPROCMIPS = 0x1115
  S_MANYREG2 = 0x1117
  S_LPROCIA64 = 0x1118
  S_GPROCIA64 = 0x1119
  S_LOCALSLOT = 0x111a
  S_PARAMSLOT = 0x111b

  # Managed code symbols.
  S_MANFRAMEREL = 0x111e
  S_MANREGISTER = 0x111f
  S_MANSLOT = 0x1120
  S_MANMANYREG = 0x1121
  S_MANREGREL = 0x1122
  S_MANMANYREG2 = 0x1123
  S_DATAREF = 0x1126
  S_ANNOTATIONREF = 0x1128
  S_TOKENREF = 0x1129
  S_GMANPROC = 0x112a
  S_LMANPROC = 0x112b
  S_ATTR_FRAMEREL = 0x112e
  S_ATTR_REGISTER = 0x112f
  S_ATTR_REGREL = 0x1130
  S_ATTR_MANYREG = 0x1131


  S_SEPCODE = 0x1132
  S_LOCAL_2005 = 0x1133
  S_DEFRANGE_2005 = 0x1134
  S_DEFRANGE2_2005 = 0x1135
  S_DISCARDED = 0x113b

  # Current symbol types for most procedures as of this writing.
  S_LPROCMIPS_ID = 0x1148
  S_GPROCMIPS_ID = 0x1149
  S_LPROCIA64_ID = 0x114a
  S_GPROCIA64_ID = 0x114b

  S_DEFRANGE_HLSL = 0x1150
  S_GDATA_HLSL = 0x1151
  S_LDATA_HLSL = 0x1152
  S_LOCAL_DPC_GROUPSHARED = 0x1154
  S_DEFRANGE_DPC_PTR_TAG = 0x1157
  S_DPC_SYM_TAG_MAP = 0x1158
  S_POGODATA = 0x115c
  S_INLINESITE2 = 0x115d
  S_MOD_TYPEREF = 0x115f
  S_REF_MINIPDB = 0x1160
  S_PDBMAP = 0x1161
  S_GDATA_HLSL32 = 0x1162
  S_LDATA_HLSL32 = 0x1163
  S_GDATA_HLSL32_EX = 0x1164
  S_LDATA_HLSL32_EX = 0x1165

  S_FASTLINK = 0x1167 # Undocumented


  # Known symbol types
  S_END = 0x0006  # ScopeEndSym
  S_INLINESITE_END = 0x114e  # alias InlineSiteEnd ScopeEndSym
  S_PROC_ID_END = 0x114f  # alias ProcEnd ScopeEndSym

  S_THUNK32 = 0x1102  # Thunk32Sym
  S_TRAMPOLINE = 0x112c  # TrampolineSym
  S_SECTION = 0x1136  # SectionSym
  S_COFFGROUP = 0x1137  # CoffGroupSym
  S_EXPORT = 0x1138  # ExportSym

  S_LPROC32 = 0x110f  # ProcSym
  S_GPROC32 = 0x1110  # alias GlobalProcSym ProcSym
  S_LPROC32_ID = 0x1146  # alias ProcIdSym ProcSym
  S_GPROC32_ID = 0x1147  # alias GlobalProcIdSym ProcSym
  S_LPROC32_DPC = 0x1155  # alias DPCProcSym ProcSym
  S_LPROC32_DPC_ID = 0x1156  # alias DPCProcIdSym ProcSym

  S_REGISTER = 0x1106  # RegisterSym
  S_PUB32 = 0x110e  # PublicSym32

  S_PROCREF = 0x1125  # ProcRefSym
  S_LPROCREF = 0x1127  # alias LocalProcRef ProcRefSym


  S_ENVBLOCK = 0x113d  # EnvBlockSym

  S_INLINESITE = 0x114d  # InlineSiteSym
  S_LOCAL = 0x113e  # LocalSym
  S_DEFRANGE = 0x113f  # DefRangeSym
  S_DEFRANGE_SUBFIELD = 0x1140  # DefRangeSubfieldSym
  S_DEFRANGE_REGISTER = 0x1141  # DefRangeRegisterSym
  S_DEFRANGE_FRAMEPOINTER_REL = 0x1142  # DefRangeFramePointerRelSym
  S_DEFRANGE_SUBFIELD_REGISTER = 0x1143  # DefRangeSubfieldRegisterSym
  S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE = 0x1144  # DefRangeFramePointerRelFullScopeSym
  S_DEFRANGE_REGISTER_REL = 0x1145  # DefRangeRegisterRelSym
  S_BLOCK32 = 0x1103  # BlockSym
  S_LABEL32 = 0x1105  # LabelSym
  S_OBJNAME = 0x1101  # ObjNameSym
  S_COMPILE2 = 0x1116  # Compile2Sym
  S_COMPILE3 = 0x113c  # Compile3Sym
  S_FRAMEPROC = 0x1012  # FrameProcSym
  S_CALLSITEINFO = 0x1139  # CallSiteInfoSym
  S_FILESTATIC = 0x1153  # FileStaticSym
  S_HEAPALLOCSITE = 0x115e  # HeapAllocationSiteSym
  S_FRAMECOOKIE = 0x113a  # FrameCookieSym

  S_ARMSWITCHTABLE = 0x1159  # JumpTableSym

  S_CALLEES = 0x115a  # CallerSym
  S_CALLERS = 0x115b  # alias CalleeSym CallerSym

  S_UDT = 0x1108  # UDTSym
  S_COBOLUDT = 0x1109  # alias CobolUDT UDTSym

  S_BUILDINFO = 0x114c  # BuildInfoSym
  S_BPREL32 = 0x110b  # BPRelativeSym
  S_REGREL32 = 0x1111  # RegRelativeSym

  S_CONSTANT = 0x1107  # ConstantSym
  S_MANCONSTANT = 0x112d  # alias ManagedConstant ConstantSym

  S_LDATA32 = 0x110c  # DataSym
  S_GDATA32 = 0x110d  # alias GlobalData DataSym
  S_LMANDATA = 0x111c  # alias ManagedLocalData DataSym
  S_GMANDATA = 0x111d  # alias ManagedGlobalData DataSym

  S_LTHREAD32 = 0x1112  # ThreadLocalDataSym
  S_GTHREAD32 = 0x1113  # alias GlobalTLS ThreadLocalDataSym

  S_UNAMESPACE = 0x1124  # UsingNamespaceSym
  S_ANNOTATION = 0x1019  # AnnotationSym

  S_HOTPATCHFUNC = 0x1169  # HotPatchFuncSym

