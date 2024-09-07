import ctypes
import enum
from ctypes import wintypes


class IMAGE_DOS_HEADER(ctypes.Structure):
  _fields_ = [
    ("e_magic", wintypes.WORD),
    ("e_cblp", wintypes.WORD),
    ("e_cp", wintypes.WORD),
    ("e_crlc", wintypes.WORD),
    ("e_cparhdr", wintypes.WORD),
    ("e_minalloc", wintypes.WORD),
    ("e_maxalloc", wintypes.WORD),
    ("e_ss", wintypes.WORD),
    ("e_sp", wintypes.WORD),
    ("e_csum", wintypes.WORD),
    ("e_ip", wintypes.WORD),
    ("e_cs", wintypes.WORD),
    ("e_lfarlc", wintypes.WORD),
    ("e_ovno", wintypes.WORD),
    ("e_res", wintypes.WORD * 4),
    ("e_oemid", wintypes.WORD),
    ("e_oeminfo", wintypes.WORD),
    ("e_res2", wintypes.WORD * 10),
    ("e_lfanew", wintypes.LONG),
  ]
  e_magic: int
  e_cblp: int
  e_cp: int
  e_crlc: int
  e_cparhdr: int
  e_minalloc: int
  e_maxalloc: int
  e_ss: int
  e_sp: int
  e_csum: int
  e_ip: int
  e_cs: int
  e_lfarlc: int
  e_ovno: int
  e_res: int
  e_oemid: int
  e_oeminfo: int
  e_res2: int
  e_lfanew: int


class IMAGE_FILE_HEADER(ctypes.Structure):
  _fields_ = [
    ("Machine", wintypes.WORD),
    ("NumberOfSections", wintypes.WORD),
    ("TimeDateStamp", wintypes.DWORD),
    ("PointerToSymbolTable", wintypes.DWORD),
    ("NumberOfSymbols", wintypes.DWORD),
    ("SizeOfOptionalHeader", wintypes.WORD),
    ("Characteristics", wintypes.WORD),
  ]
  Machine: int
  NumberOfSections: int
  TimeDateStamp: int
  PointerToSymbolTable: int
  NumberOfSymbols: int
  SizeOfOptionalHeader: int
  Characteristics: int


class IMAGE_DATA_DIRECTORY(ctypes.Structure):
  _fields_ = [
    ("VirtualAddress", wintypes.DWORD),
    ("Size", wintypes.DWORD),
  ]
  VirtualAddress: int
  Size: int


IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16


class IMAGE_OPTIONAL_HEADER32(ctypes.Structure):
  _fields_ = [
    ("Magic", wintypes.WORD),
    ("MajorLinkerVersion", wintypes.BYTE),
    ("MinorLinkerVersion", wintypes.BYTE),
    ("SizeOfCode", wintypes.DWORD),
    ("SizeOfInitializedData", wintypes.DWORD),
    ("SizeOfUninitializedData", wintypes.DWORD),
    ("AddressOfEntryPoint", wintypes.DWORD),
    ("BaseOfCode", wintypes.DWORD),
    ("BaseOfData", wintypes.DWORD),
    ("ImageBase", wintypes.DWORD),
    ("SectionAlignment", wintypes.DWORD),
    ("FileAlignment", wintypes.DWORD),
    ("MajorOperatingSystemVersion", wintypes.WORD),
    ("MinorOperatingSystemVersion", wintypes.WORD),
    ("MajorImageVersion", wintypes.WORD),
    ("MinorImageVersion", wintypes.WORD),
    ("MajorSubsystemVersion", wintypes.WORD),
    ("MinorSubsystemVersion", wintypes.WORD),
    ("Win32VersionValue", wintypes.DWORD),
    ("SizeOfImage", wintypes.DWORD),
    ("SizeOfHeaders", wintypes.DWORD),
    ("CheckSum", wintypes.DWORD),
    ("Subsystem", wintypes.WORD),
    ("DllCharacteristics", wintypes.WORD),
    ("SizeOfStackReserve", wintypes.DWORD),
    ("SizeOfStackCommit", wintypes.DWORD),
    ("SizeOfHeapReserve", wintypes.DWORD),
    ("SizeOfHeapCommit", wintypes.DWORD),
    ("LoaderFlags", wintypes.DWORD),
    ("NumberOfRvaAndSizes", wintypes.DWORD),
    ("DataDirectory", IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES),
  ]
  Magic: int
  MajorLinkerVersion: int
  MinorLinkerVersion: int
  SizeOfCode: int
  SizeOfInitializedData: int
  SizeOfUninitializedData: int
  AddressOfEntryPoint: int
  BaseOfCode: int
  BaseOfData: int
  ImageBase: int
  SectionAlignment: int
  FileAlignment: int
  MajorOperatingSystemVersion: int
  MinorOperatingSystemVersion: int
  MajorImageVersion: int
  MinorImageVersion: int
  MajorSubsystemVersion: int
  MinorSubsystemVersion: int
  Win32VersionValue: int
  SizeOfImage: int
  SizeOfHeaders: int
  CheckSum: int
  Subsystem: int
  DllCharacteristics: int
  SizeOfStackReserve: int
  SizeOfStackCommit: int
  SizeOfHeapReserve: int
  SizeOfHeapCommit: int
  LoaderFlags: int
  NumberOfRvaAndSizes: int
  DataDirectory: IMAGE_DATA_DIRECTORY * IMAGE_NUMBEROF_DIRECTORY_ENTRIES


class IMAGE_NT_HEADERS32(ctypes.Structure):
  _fields_ = [
    ("Signature", wintypes.DWORD),
    ("FileHeader", IMAGE_FILE_HEADER),
    ("OptionalHeader", IMAGE_OPTIONAL_HEADER32),
  ]
  Signature: int
  FileHeader: IMAGE_FILE_HEADER
  OptionalHeader: IMAGE_OPTIONAL_HEADER32


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


class IMAGE_BASE_RELOCATION(ctypes.Structure):
  _fields_ = [
    ("VirtualAddress", wintypes.DWORD),
    ("SizeOfBlock", wintypes.DWORD),
  ]
  VirtualAddress: int
  SizeOfBlock: int


class IMAGE_REL_BASED(enum.IntEnum):
  ABSOLUTE           = 0
  HIGH               = 1
  LOW                = 2
  HIGHLOW            = 3
  HIGHADJ            = 4
  MACHINE_SPECIFIC_5 = 5
  RESERVED           = 6
  MACHINE_SPECIFIC_7 = 7
  MACHINE_SPECIFIC_8 = 8
  MACHINE_SPECIFIC_9 = 9
  DIR64              = 10


class IMAGE_DIRECTORY_ENTRY(enum.IntEnum):
  EXPORT         =  0   # Export Directory
  IMPORT         =  1   # Import Directory
  RESOURCE       =  2   # Resource Directory
  EXCEPTION      =  3   # Exception Directory
  SECURITY       =  4   # Security Directory
  BASERELOC      =  5   # Base Relocation Table
  DEBUG          =  6   # Debug Directory
  ARCHITECTURE   =  7   # Architecture Specific Data
  GLOBALPTR      =  8   # RVA of GP
  TLS            =  9   # TLS Directory
  LOAD_CONFIG    = 10   # Load Configuration Directory
  BOUND_IMPORT   = 11   # Bound Import Directory in headers
  IAT            = 12   # Import Address Table
  DELAY_IMPORT   = 13   # Delay Load Import Descriptors
  COM_DESCRIPTOR = 14   # COM Runtime descriptor


class IMAGE_EXPORT_DIRECTORY(ctypes.Structure):
  _fields_ = [
    ("Characteristics", wintypes.DWORD),
    ("TimeDateStamp", wintypes.DWORD),
    ("MajorVersion", wintypes.WORD),
    ("MinorVersion", wintypes.WORD),
    ("Name", wintypes.DWORD),
    ("Base", wintypes.DWORD),
    ("NumberOfFunctions", wintypes.DWORD),
    ("NumberOfNames", wintypes.DWORD),
    ("AddressOfFunctions", wintypes.DWORD),
    ("AddressOfNames", wintypes.DWORD),
    ("AddressOfNameOrdinals", wintypes.DWORD),
  ]
  Characteristics: int
  TimeDateStamp: int
  MajorVersion: int
  MinorVersion: int
  Name: int
  Base: int
  NumberOfFunctions: int
  NumberOfNames: int
  AddressOfFunctions: int
  AddressOfNames: int
  AddressOfNameOrdinals: int


class IMAGE_IMPORT_DESCRIPTOR(ctypes.Structure):
  _fields_ = [
    ("OriginalFirstThunk", wintypes.DWORD),
    ("TimeDateStamp", wintypes.DWORD),
    ("ForwarderChain", wintypes.DWORD),
    ("Name", wintypes.DWORD),
    ("FirstThunk", wintypes.DWORD),
  ]
  OriginalFirstThunk: int
  TimeDateStamp: int
  ForwarderChain: int
  Name: int
  FirstThunk: int


IMAGE_ORDINAL_FLAG = 0x80000000
IMAGE_SCN_CNT_CODE = 0x00000020  # Section contains code.
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040  # Section contains initialized data.
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080  # Section contains uninitialized data.
IMAGE_SCN_MEM_EXECUTE = 0x20000000  # Section is executable.
IMAGE_SCN_MEM_READ = 0x40000000  # Section is readable.
IMAGE_SCN_MEM_WRITE = 0x80000000  # Section is writeable.

def format_acc(chars):
  val = []
  val.append('R' if chars & IMAGE_SCN_MEM_READ else '-')
  val.append('W' if chars & IMAGE_SCN_MEM_WRITE else '-')
  val.append('X' if chars & IMAGE_SCN_MEM_EXECUTE else '-')
  return val


IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3
