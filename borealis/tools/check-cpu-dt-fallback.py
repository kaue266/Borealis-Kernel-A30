#!/usr/bin/env python3
"""Check pinned CPU sources/host tests before the queued full kernel build."""
from pathlib import Path
import argparse
import hashlib
import json
import subprocess

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--apply', action='store_true', help='Apply the pinned CPU patch only to its exact predecessor')
args = parser.parse_args()
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
record = json.loads((package / 'validation/kernel/cpu-dt-fallback-source-port.json').read_text())
host = json.loads((package / 'validation/kernel/cpu-dt-fallback-tests.json').read_text())
assert sha(package / 'kernel-patches/r24u-cpu-dt-fallback.patch') == record['patch_sha256']
assert record['host_tested'] and host['passed'] and host['asan_ubsan'] == 'passed'
assert host['original_fallback_failures_reproduced'] == 3 and host['config_disabled_qos_behavior_preserved']
assert record['changed_files'] == host['source_sha256']
assert not host['device_tested'] and not host['init_domain_full_function_executed']
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=kernel, text=True).strip() == 'e1b8464bb29ce5bcb9d52bfcfc71bc2563e12563'
actual = {n: sha(kernel / n) for n in record['changed_files']}
if actual != record['changed_files']:
    assert actual == record['before_sha256'], 'Unexpected/partial CPU sources; nothing changed'
    assert args.apply, 'Pinned CPU predecessor found; add --apply to apply the inspected patch'
    patch = package / 'kernel-patches/r24u-cpu-dt-fallback.patch'
    subprocess.run(['git', 'apply', '--check', str(patch)], cwd=kernel, check=True)
    subprocess.run(['git', 'apply', str(patch)], cwd=kernel, check=True)
    assert {n: sha(kernel / n) for n in record['changed_files']} == record['changed_files']
print('CPU DT fallback source/host evidence verified; full native linkage and hardware remain pending.')
