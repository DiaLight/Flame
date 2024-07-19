import pathlib
import os
import shutil

import git
import git.exc


def read_message(file: pathlib.Path):
  with open(file, 'r') as f:
    for i in range(8):
      line = f.readline()
      if line.startswith('Subject: [PATCH] '):
        return line.rstrip()[len('Subject: [PATCH] '):]
  raise Exception("message not found")


def failed_changed_repo(message):
  print(f"repo already exists in src and {message}")
  print("delete src directory to apply existing patches or rebuild patches from your changes")
  exit(-1)


def assert_no_new_changes(repo: git.Repo, patches: list[pathlib.Path]):
  commits = [commit.message.rstrip() for commit in repo.iter_commits()]
  patches = [read_message(file) for file in reversed(patches)]
  if commits != patches:
    return failed_changed_repo("some commit changes are made")
  if repo.untracked_files:
    return failed_changed_repo("there new files in repo")
  if repo.index.diff(None):
    return failed_changed_repo("there unstaged changes")
  if repo.index.diff("HEAD"):
    return failed_changed_repo("there staged changes")


def main():
  patches_dir = pathlib.Path(__file__).parent / 'patches'
  patches = [file for file in patches_dir.iterdir() if file.name.endswith('.patch')]

  repo_dir = pathlib.Path(__file__).parent / 'src'

  if not repo_dir.exists():
    repo_dir.mkdir()

  try:
    repo = git.Repo(repo_dir)
    if repo.branches:  # not empty repo
      try:
        repo.git.am("--abort")
      except git.exc.GitError:
        pass
      assert_no_new_changes(repo, patches)
      print("reapply patches")
      shutil.rmtree(repo_dir, ignore_errors=True)
      repo = git.Repo.init(repo_dir, initial_branch='main')
  except git.exc.GitError:
    repo = git.Repo.init(repo_dir, initial_branch='main')
  os.chdir(repo.working_dir)

  # repo.git.am("--3way", *[f"../patches/{file.name}" for file in patches])
  for file in patches:
    print(f"apply {file}")
    repo.git.am("--3way", f"../patches/{file.name}")


if __name__ == '__main__':
  main()

