#!/usr/bin/env python3
"""Reconstruct all pinned patches from recorded predecessors in a temporary tree."""
from pathlib import Path
import hashlib
import json
import subprocess
import tempfile

package = Path(__file__).resolve().parent.parent
stages = [
    ('bpf-sockopt', '0001-r24u-cgroup-sockopt.patch'),
    ('bpf-batch', '0002-r24u-map-batch.patch'),
    ('bpf-socket-pointer', '0003-r24u-borrowed-socket.patch'),
]
if (package / 'validation/bpf-mmap-source-port.json').is_file():
    stages.append(('bpf-mmap', '0004-r24u-array-mmap.patch'))
if (package / 'validation/bpf-socket-release-source-port.json').is_file():
    stages.append(('bpf-socket-release', '0005-r24u-socket-release.patch'))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
records = [(json.loads((package / f'validation/{name}-source-port.json').read_text()),
            package / ('kernel-patches/' + patch), package / f'validation/{name}-before')
           for name, patch in stages]
baseline, prior = {}, {}
for index, (record, patch, backup) in enumerate(records):
    assert sha(patch) == record['patch_sha256']
    if index: assert record['predecessor_patch_sha256'] == records[index - 1][0]['patch_sha256']
    for name, value in record['before_sha256'].items():
        if name in prior:
            assert prior[name] == value, 'Invalid predecessor: ' + name
        else:
            if value is None:
                # The original port stored a zero-byte placeholder for files
                # absent before the patch. Do not materialize that placeholder.
                assert not (backup / name).exists() or (backup / name).stat().st_size == 0
            else:
                assert sha(backup / name) == value, 'Invalid baseline backup: ' + name
            baseline[name] = backup / name if value is not None else None
    prior.update(record['changed_files'])

results = []
with tempfile.TemporaryDirectory(prefix='borealis-bpf-chain-') as temp:
    tree = Path(temp)
    for name, source in baseline.items():
        if source is not None:
            target = tree / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.read_bytes())
    state = {name: sha(tree / name) for name in baseline}
    for (stage, _), (record, patch, _) in zip(stages, records):
        subprocess.run(['git', 'apply', '--check', str(patch)], cwd=tree, check=True)
        subprocess.run(['git', 'apply', str(patch)], cwd=tree, check=True)
        state.update(record['changed_files'])
        assert {name: sha(tree / name) for name in state} == state
        results.append({'stage': stage, 'source_hashes_verified': True, 'patch_sha256': sha(patch)})
    # An overlapping patch cannot be silently applied twice.
    rejected = subprocess.run(['git', 'apply', '--check', str(records[-1][1])], cwd=tree,
                               capture_output=True)
    assert rejected.returncode != 0
    assert {name: sha(tree / name) for name in state} == state
report = {'scope': f'Reconstruct {len(stages)} source patches in an isolated temporary tree',
          'stages': results, 'duplicate_patch_rejected_without_changes': True,
          'passed': True, 'kernel_linked': False, 'device_tested': False}
(package / 'validation/bpf-backport-chain-tests.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
