import pathlib
import os
import re
import shutil

import git.exc
from git import Repo


HASH1_RE = re.compile("From ([a-z0-9]{32,}) (.*)")


def hash1_re(m: re.Match):
  hash = '0' * len(m.group(1))
  return f"From {hash} {m.group(2)}"


HASH2_RE = re.compile("index ([a-z0-9]{7,})\\.\\.([a-z0-9]{7,})(.*)")


def hash2_re(m: re.Match):
  hash = '0' * len(m.group(1))
  return f"index {hash}..{hash}{m.group(3)}"


def cleanup_line(line: str):
  line = HASH1_RE.sub(hash1_re, line)
  line = HASH2_RE.sub(hash2_re, line)
  return line


def cleanup_patch(file: pathlib.Path):
  print('cleanup', file)
  with open(file, 'r') as f:
    lines = f.readlines()

  lines = [cleanup_line(line) for line in lines]
  assert lines[-3].rstrip() == '--'
  del lines[-3]
  del lines[-2]
  del lines[-1]

  with open(file, 'w') as f:
    f.writelines(lines)


def main():
  patches_dir = pathlib.Path(__file__).parent / 'patches'
  repo_dir = pathlib.Path(__file__).parent / 'src'

  if patches_dir.exists():
    shutil.rmtree(patches_dir, ignore_errors=True)
  patches_dir.mkdir()

  repo_dir.mkdir(exist_ok=True)

  try:
    repo = Repo(repo_dir)
  except git.exc.GitError:
    print("no repo to build patches from")
    exit(-1)
  os.chdir(repo.working_dir)

  repo.git.format_patch(
    "--no-stat",  # Generate plain patches without any diffstats
    "--minimal",  # Spend extra time to make sure the smallest possible diff is produced
    "-N",  # Name output in [PATCH] format
    "-o", "../patches",  # output dir
    "-10000", "main"  # from to
  )
  patches = [file for file in patches_dir.iterdir() if file.name.endswith('.patch')]
  for file in patches:
    cleanup_patch(file)

  print("patches rebuilt")


if __name__ == '__main__':
  main()
