import bisect
import enum
import typing


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

        # self._ty: my_pdb.FrameType = None

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

def fpobin_serialize(f: typing.BinaryIO, fpos: list[MyFpoFun]):
    write_varint(f, len(fpos))
    last_va = 0
    for mfpo in fpos:
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
