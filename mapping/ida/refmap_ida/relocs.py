import os
import pathlib
import typing
import bisect
from .kind import Kind
from .flags import Flags
from . import RANGES


class Reloc:

  def __init__(self, src, value, dst, kind: Kind):
    self.src_va = src
    self.value = value
    self.dst_va = dst
    self.kind = kind

  def merge(self, rel):
    assert self.dst_va == rel.dst_va
    assert self.kind == rel.kind


class Relocs:

  def __init__(self, file_path: pathlib.Path):
    self.file_path = file_path
    self.relocs_rva = []  # type: typing.List[int]
    self.relocs = []  # type: typing.List[Reloc]

  def find_le(self, rva: int) -> Reloc:
    idx = bisect.bisect_right(self.relocs_rva, rva) - 1
    if idx == -1:
      return None
    return self.relocs[idx]

  def get(self, va):
    bl = self.find_le(va - RANGES.img_base)
    if bl is None:
      return None
    if va != bl.src_va:
      return None
    return bl

  def add(self, rel: Reloc):
    ridx = bisect.bisect_left(self.relocs_rva, rel.src_va - RANGES.img_base)
    if ridx == len(self.relocs_rva):
      self.relocs.append(rel)
      self.relocs_rva.append(rel.src_va - RANGES.img_base)
      return True
    if self.relocs[ridx].src_va == rel.src_va:
      self.relocs[ridx].merge(rel)
      return False
    self.relocs.insert(ridx, rel)
    self.relocs_rva.insert(ridx, rel.src_va - RANGES.img_base)
    return True

  def read(self):
    if not self.file_path.exists():
      return
    with open(self.file_path, "r") as f:
      lnum = -1
      for line in f.readlines():
        lnum += 1
        line = line.rstrip()
        if line.startswith("#"):
          continue
        split = line.split(' ', 3)
        if len(split) != 4:
          raise Exception(f"bad size {lnum} {split}")
        src, value, dst, kind = split
        kind = Kind.parse(kind)
        assert kind is not None
        reloc = Reloc(
          int(src, 16),
          int(value, 16),
          int(dst, 16),
          kind
        )
        self.add(reloc)

  def write(self):
    with open(self.file_path, "w") as f:
      f.write("## binary references mapping\n")
      f.write("# src_va value dst_va kind\n")
      for rel in self.relocs:
        line = "%08X %08X %08X %s" % (rel.src_va, rel.value, rel.dst_va, rel.kind.format())
        f.write(line + "\n")
