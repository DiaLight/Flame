
### add new patch
```bat
cd src
:: make changes
git add .
git commit -m"fix_improve_whatever"
python ../rebuild_patches.py
```

### edit existing patch
```bat
cd src
gitk --all  & :: locate hash of commit
git checkout <hash>
:: make changes
git add .
git commit --amend --no-edit
git rebase --onto HEAD <hash> main
git checkout main
python ../rebuild_patches.py
```

### get first commit hash
```bat
git rev-list --max-parents=0 HEAD
```
