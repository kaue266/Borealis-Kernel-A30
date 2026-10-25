#!/usr/bin/env python3
"""Check or apply the pinned, bounded R24U socket-option backport."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--kernel', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    package = Path(__file__).resolve().parent.parent
    record = json.loads((package / 'validation/bpf-sockopt-source-port.json').read_text())
    kernel = args.kernel.resolve(strict=True)
    patch = package / 'kernel-patches/0001-r24u-cgroup-sockopt.patch'
    if sha(patch) != record['patch_sha256']:
        raise RuntimeError('Patch hash differs from the validated backport')
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=kernel, text=True).strip()
    if commit != record['kernel_commit']:
        raise RuntimeError('Kernel commit differs from the R24U baseline')
    actual = {name: sha(kernel / name) for name in record['changed_files']}
    if actual == record['changed_files']:
        print('Backport already present; every affected source hash matches.')
        return
    if actual != record['before_sha256']:
        changed = [name for name in actual if actual[name] != record['before_sha256'][name]]
        raise RuntimeError('Unexpected or partial source state; no files changed: ' + ', '.join(changed))
    subprocess.run(['git', 'apply', '--check', str(patch)], cwd=kernel, check=True)
    if not args.apply:
        print('Pinned baseline and patch applicability verified; no source files changed.')
        return
    # git apply prevalidates the complete patch. No --reject or partial hunks.
    subprocess.run(['git', 'apply', str(patch)], cwd=kernel, check=True)
    actual = {name: sha(kernel / name) for name in record['changed_files']}
    if actual != record['changed_files']:
        raise RuntimeError('Post-apply hashes differ; keep this checkout out of builds')
    print('R24U backport applied and source hashes verified; full kernel/runtime tests remain required.')


if __name__ == '__main__':
    main()
