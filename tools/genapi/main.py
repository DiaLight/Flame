import argparse
import pathlib
import sgmap
from gen_utils import is_vtable, build_struct_path
from gen_struct_cpp import format_struct_cpp
from gen_struct_h import format_struct_h
from gen_globals_cpp import format_globals_cpp
from gen_globals_h import format_globals_h
from gen_functions_cpp import format_functions_cpp
from gen_functions_h import format_functions_h


def build_vtable_map(globals: list[sgmap.Global]) -> dict[str, sgmap.Global]:
  vtable_map = {}
  for glob in filter(is_vtable, globals):
    stru_t = glob.type  # type: sgmap.StructType
    vtable_map[stru_t.struct.id] = glob
  return vtable_map


def gen_structures(
    include_dir: pathlib.Path,
    structs_map: dict[str, sgmap.Struct],
    vtable_map: dict[str, sgmap.Global]):

  def gen_structures_h():
    # generate new structures
    for struct in structs_map.values():
      struct_path = build_struct_path(struct, 'h')
      print(f'create {struct_path}')
      new_path = include_dir / struct_path
      new_path.parent.mkdir(parents=True, exist_ok=True)
      with open(new_path, 'w') as f:
        for line in format_struct_h(struct, vtable_map):
          f.write(line + "\n")
  gen_structures_h()


def gen_globals(include_dir: pathlib.Path, globals: list[sgmap.Global]):

  def gen_globals_h():
    file_h = include_dir / f"dk2_globals.h"
    if file_h.exists():
      with open(file_h, 'r') as f:
        lines = f.readlines()
      lines = list(map(str.rstrip, lines))
      new_lines = list(format_globals_h(globals))
      if lines != new_lines:
        print(f'update {file_h.name}')
        with open(file_h, 'w') as f:
          for line in new_lines:
            f.write(line)
            f.write("\n")
    else:
      print(f'create {file_h.name}')
      with open(file_h, 'w') as f:
        for line in format_globals_h(globals):
          f.write(line + "\n")
  gen_globals_h()


def gen_functions(include_dir: pathlib.Path, globals: list[sgmap.Global]):

  def gen_functions_h():
    file_h = include_dir / f"dk2_functions.h"
    if file_h.exists():
      with open(file_h, 'r') as f:
        lines = f.readlines()
      lines = list(map(str.rstrip, lines))
      new_lines = list(format_functions_h(globals))
      if lines != new_lines:
        print(f'update {file_h.name}')
        with open(file_h, 'w') as f:
          for line in new_lines:
            f.write(line)
            f.write("\n")
    else:
      print(f'create {file_h.name}')
      with open(file_h, 'w') as f:
        for line in format_functions_h(globals):
          f.write(line + "\n")
  gen_functions_h()


def main(sgmap_file: pathlib.Path, include_dir: pathlib.Path):
  structs, globals = sgmap.parse_file(sgmap_file)
  print(f'{len(structs)} {len(globals)}')
  structs_map = {struct.id: struct for struct in structs}

  vtable_map = build_vtable_map(globals)
  gen_structures(include_dir, structs_map, vtable_map)
  gen_globals(include_dir, globals)
  gen_functions(include_dir, globals)


def start():
  parser = argparse.ArgumentParser(description='Optional app description')
  parser.add_argument('-sgmap_file', type=str, required=True)
  parser.add_argument('-headers', type=str, required=True)
  args = parser.parse_args()
  main(pathlib.Path(args.sgmap_file), pathlib.Path(args.headers))


if __name__ == '__main__':
  start()
