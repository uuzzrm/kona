"""Bounded workspace change discovery and policy classification."""
from __future__ import annotations
from dataclasses import dataclass
import fnmatch, hashlib, os
from pathlib import Path
from typing import Any, Iterable

DEFAULT_MAX_CHANGED_PATHS = 100
MAX_WORKSPACE_ENTRIES = 10_000
MAX_WORKSPACE_HASH_BYTES = 512 * 1024 * 1024
class WorkspacePolicyError(ValueError): pass
@dataclass(frozen=True)
class WorkspacePolicy:
    mode: str
    allow: tuple[str, ...]
    deny: tuple[str, ...]
    max_changed_paths: int
def _digest(path: Path, budget: list[int]) -> str:
    value=hashlib.sha256()
    with path.open('rb') as handle:
        for chunk in iter(lambda: handle.read(1024*1024), b''):
            budget[0] += len(chunk)
            if budget[0] > MAX_WORKSPACE_HASH_BYTES: raise WorkspacePolicyError(f'workspace exceeds {MAX_WORKSPACE_HASH_BYTES} hashed bytes')
            value.update(chunk)
    return value.hexdigest()
def snapshot_workspace(root: Path, *, excluded_roots: Iterable[Path]=()) -> dict[str,dict[str,Any]]:
    root=root.resolve(); excluded={p.resolve() for p in excluded_roots}; result={}; count=0; budget=[0]
    def traversal_error(error: OSError) -> None: raise WorkspacePolicyError(f'could not scan workspace: {error}')
    for current, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=traversal_error):
        base=Path(current); kept=[]
        for name in sorted(dirs):
            try:
                child=base/name
                if name=='.git' or child.resolve() in excluded: continue
                relative=child.relative_to(root).as_posix()
                if child.is_symlink(): result[relative]={'kind':'symlink'}
                else: result[relative]={'kind':'directory'}; kept.append(name)
                count+=1
            except OSError as error: raise WorkspacePolicyError(f'could not inspect workspace entry: {child}') from error
        dirs[:]=kept
        for name in sorted(files):
            child=base/name
            try:
                if child.resolve() in excluded: continue
                relative=child.relative_to(root).as_posix()
                if child.is_symlink(): metadata={'kind':'symlink'}
                elif child.is_file(): metadata={'kind':'file','size':child.stat().st_size,'sha256':_digest(child,budget)}
                else: metadata={'kind':'special'}
            except OSError as error: raise WorkspacePolicyError(f'could not inspect workspace entry: {child}') from error
            result[relative]=metadata; count+=1
            if count>MAX_WORKSPACE_ENTRIES: raise WorkspacePolicyError(f'workspace exceeds {MAX_WORKSPACE_ENTRIES} entries')
    return result
def evaluate_workspace_policy(policy: WorkspacePolicy, before: dict[str,dict[str,Any]], after: dict[str,dict[str,Any]]) -> dict[str,Any]:
    changed=[]
    for path in sorted(set(before)|set(after)):
        if before.get(path)==after.get(path): continue
        change='created' if path not in before else 'deleted' if path not in after else 'modified'
        changed.append({'path':path,'change':change})
    if len(changed)>policy.max_changed_paths: raise WorkspacePolicyError(f'workspace changed {len(changed)} paths; limit is {policy.max_changed_paths}')
    matches=lambda p, patterns:any(fnmatch.fnmatchcase(p,g) for g in patterns)
    denied=[x['path'] for x in changed if matches(x['path'],policy.deny)]
    allowed=[x['path'] for x in changed if not matches(x['path'],policy.deny) and matches(x['path'],policy.allow)]
    unexpected=[x['path'] for x in changed if x['path'] not in denied and x['path'] not in allowed]
    return {'mode':policy.mode,'valid':not denied and not unexpected,'changed':changed,
      'changed_paths':[x['path'] for x in changed],
      'created':[x['path'] for x in changed if x['change']=='created'],
      'modified':[x['path'] for x in changed if x['change']=='modified'],
      'deleted':[x['path'] for x in changed if x['change']=='deleted'],
      'allowed':allowed,'denied':denied,'unexpected':unexpected,'max_changed_paths':policy.max_changed_paths,
      'after':{x['path']:after.get(x['path'],{'kind':'missing'}) for x in changed}}
