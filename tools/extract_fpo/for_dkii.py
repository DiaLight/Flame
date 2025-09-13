import argparse
import io
import pathlib
import sys

from my_fpo import MyFpoFun, fpobin_serialize


def read_espmap(dkii_espmap_file: pathlib.Path) -> list[MyFpoFun]:
    result: list[MyFpoFun] = []
    fpo = None
    for line in dkii_espmap_file.read_text().splitlines():
        if line.startswith('#'):
            continue
        if not line.startswith(' '):
            va, name = line.split(' ', 1)
            va = int(va, 16)
            fpo = MyFpoFun(va, name)
            result.append(fpo)
        else:
            assert fpo is not None
            line = line[1:]
            split = line.split(' ', 4)
            assert len(split) in [4, 5]
            va, spd, kind, delta, *cmt = split
            if kind == 'jmp':
                target = int(delta, 16)
                delta = '0'
            va, spd, delta = int(va, 16), int(spd), int(delta)
            if kind == 'sp':
                kind = 0
            elif kind == 'jmp':
                kind = 1
            elif kind == 'ret':
                kind = 2
            else:
                raise Exception(kind)
            fpo.add_ida(va, -spd, kind)
    return result

def main(espmap_file: pathlib.Path, fpo_file: pathlib.Path):
    fpos = read_espmap(espmap_file)
    with fpo_file.open('wb') as f:
        fpobin_serialize(f, fpos)

def start():
    parser = argparse.ArgumentParser()
    # in
    parser.add_argument('-espmap_file', type=str, required=True)
    # out
    parser.add_argument('-fpo_file', type=str, required=True)
    args = parser.parse_args()
    print(' '.join(sys.argv))
    main(
        pathlib.Path(args.espmap_file),
        pathlib.Path(args.fpo_file),
    )


if __name__ == '__main__':
    start()
