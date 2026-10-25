#!/usr/bin/env python3
"""Capture source correspondence before/after a complete kernel pair build."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--verify', action='store_true')
args = parser.parse_args()
package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
changed = subprocess.check_output(['git', 'diff', '--name-only', 'HEAD'], cwd=kernel, text=True).splitlines()
changed.append('kernel/bpf/sockopt.c')
patch = subprocess.check_output(['git', 'diff', '--binary', 'HEAD'], cwd=kernel)
record = {'kernel_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=kernel, text=True).strip(),
          'tracked_worktree_patch_sha256': hashlib.sha256(patch).hexdigest(),
          'changed_source_sha256': {n: sha(kernel / n) for n in sorted(set(changed))},
          'kernelsu_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=kernel / 'KernelSU', text=True).strip(),
          'backport_patch_sha256': {n: sha(package / 'kernel-patches' / n) for n in
                                   ['0001-r24u-cgroup-sockopt.patch', '0002-r24u-map-batch.patch',
                                    '0003-r24u-borrowed-socket.patch', '0004-r24u-array-mmap.patch',
                                    '0005-r24u-socket-release.patch',
                                    '0006-r24u-wipeonfork.patch']}}
assert record['kernel_commit'] == 'e1b8464bb29ce5bcb9d52bfcfc71bc2563e12563'
assert record['kernelsu_commit'] == '109442f8c4c7692af6562bdad6fd9f39dc1f935b'
assert not subprocess.check_output(['git', 'diff', '--binary', 'HEAD'], cwd=kernel / 'KernelSU')
path = package / 'validation/kernel/build-source-start.json'
if args.verify:
    assert record == json.loads(path.read_text()), 'Kernel sources changed during compilation'
    print('Kernel source hashes match the start of the complete pair build.')
else:
    (package / 'kernel-patches/r24u-complete-worktree.patch').write_bytes(patch)
    path.write_text(json.dumps(record, indent=2) + '\n')
    print('Full kernel worktree patch and changed-source hashes captured before build.')
