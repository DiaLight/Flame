import idc
import idaapi
import idautils
import pathlib
import os.path


def apply_map(map_file=None):
  if map_file is None:
    exe_file = pathlib.Path(idaapi.get_input_file_path())
    map_file = exe_file.parent / f'{os.path.splitext(exe_file.name)[0]}.map'
  else:
    map_file = pathlib.Path(map_file)
  if map_file.exists():
    with open(map_file, 'r') as f:
      lines = f.readlines()
    for line in lines:
      line = line.rstrip()
      va, name = line.split(' ', 1)
      va = int(va, 16)
      idaapi.set_name(va, name, idaapi.SN_NOCHECK)


def get_teb():
  return idaapi.dbg_get_thread_sreg_base(idaapi.get_current_thread(), idautils.cpu.fs)
