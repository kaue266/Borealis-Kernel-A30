#!/usr/bin/env python3
"""Check/apply pinned BPF ports in order, rejecting unexpected sources."""
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
    kernel = args.kernel.resolve(strict=True)
    names = [('bpf-sockopt-source-port.json', '0001-r24u-cgroup-sockopt.patch'),
             ('bpf-batch-source-port.json', '0002-r24u-map-batch.patch'),
             ('bpf-socket-pointer-source-port.json', '0003-r24u-borrowed-socket.patch')]
    if (package / 'validation/bpf-mmap-source-port.json').is_file():
        names.append(('bpf-mmap-source-port.json', '0004-r24u-array-mmap.patch'))
    if (package / 'validation/bpf-socket-release-source-port.json').is_file():
        names.append(('bpf-socket-release-source-port.json', '0005-r24u-socket-release.patch'))
    stages = [(json.loads((package / 'validation' / report).read_text()),
               package / 'kernel-patches' / patch) for report, patch in names]
    commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=kernel, text=True).strip()
    assert all(commit == record['kernel_commit'] and sha(patch) == record['patch_sha256']
               for record, patch in stages), 'Unpinned kernel or changed patch'
    baseline = {}
    previous = {}
    for index, (record, patch) in enumerate(stages):
        if index:
            assert record['predecessor_patch_sha256'] == stages[index - 1][0]['patch_sha256']
        for name, value in record['before_sha256'].items():
            if name in previous:
                assert value == previous[name], 'Broken patch dependency: ' + name
            else:
                baseline[name] = value
        previous.update(record['changed_files'])
    states = [baseline]
    for record, patch in stages:
        states.append({**states[-1], **record['changed_files']})
    actual = {name: sha(kernel / name) for name in states[-1]}
    if actual == states[-1]:
        print(f'All {len(stages)} BPF backports are present; affected source hashes match.')
        return
    if actual not in states:
        raise RuntimeError('Unexpected or partial kernel source state; no changes made')
    start = states.index(actual)
    if not args.apply:
        subprocess.run(['git', 'apply', '--check', str(stages[start][1])], cwd=kernel, check=True)
        print('Pinned predecessor verified; next backport applies. Add --apply to apply the remaining ports.')
        return
    for index in range(start, len(stages)):
        record, patch = stages[index]
        subprocess.run(['git', 'apply', '--check', str(patch)], cwd=kernel, check=True)
        subprocess.run(['git', 'apply', str(patch)], cwd=kernel, check=True)
        assert {name: sha(kernel / name) for name in states[-1]} == states[index + 1]
    print(f'All {len(stages)} source backports applied and verified; kernel/device validation still required.')


if __name__ == '__main__':
    main()
