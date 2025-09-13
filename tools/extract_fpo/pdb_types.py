import ctypes
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
    ("Machine", wintypes.DWORD),
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
  ModuleSymStream: int
  SymByteSize: int
  oldLineSize: int
  lineSize: int
  nSrcFiles: int
  offsets: int
  niSource: int
  niCompiler: int


class SstFileIndex(ctypes.Structure):
  _fields_ = [
    ("cMod", wintypes.WORD),
    ("cRef", wintypes.WORD),
  ]
  cMod: int
  cRef: int


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

