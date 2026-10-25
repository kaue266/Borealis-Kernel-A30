#!/usr/bin/env python3
"""Bind socket host/native evidence to installed sources; never approve boot."""
from pathlib import Path
import hashlib
import json

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
sha = lambda path: hashlib.sha256(path.read_bytes()).hexdigest()
report_path = package / 'validation/bpf-socket-pointer-source-port.json'
if (package / 'validation/bpf-mmap-source-port.json').is_file():
    report_path = package / 'validation/bpf-mmap-source-port.json'
if (package / 'validation/bpf-socket-release-source-port.json').is_file():
    report_path = package / 'validation/bpf-socket-release-source-port.json'
record = json.loads(report_path.read_text())
native_prefix = report_path.name.removesuffix('-source-port.json')
native = json.loads((package / ('validation/' + native_prefix + '-native-proof.json')).read_text())
host = json.loads((package / 'validation/bpf-socket-pointer-tests.json').read_text())
chain = json.loads((package / 'validation/bpf-backport-chain-tests.json').read_text())
assert native['affected_units_compile_passed'] and not native['full_kernel_link_passed']
assert not native['device_tested'] and not host['device_tested']
assert host['asan_ubsan'] == 'passed' and all(r['passed'] for r in host['variants'].values())
assert chain['passed'] and chain['stages'][-1]['patch_sha256'] == record['patch_sha256']
patch_name = {'bpf-socket-release': '0005-r24u-socket-release.patch',
              'bpf-mmap': '0004-r24u-array-mmap.patch',
              'bpf-socket-pointer': '0003-r24u-borrowed-socket.patch'}[native_prefix]
assert sha(package / 'kernel-patches' / patch_name) == record['patch_sha256']
assert all(sha(kernel / name) == value for name, value in record['changed_files'].items())
assert all(sha(kernel / name) == value for name, value in host['source_sha256'].items())
assert all(sha(kernel / name) == value for name, value in native['source_correspondence']['changed_source_sha256'].items())
record.update(affected_units_compile_passed=True, host_security_translation_cases=host['cases'],
              patch_reconstruction_passed=True, full_kernel_link_passed=False,
              device_tested=False, android17_network_validated=False)
if native_prefix in ('bpf-mmap', 'bpf-socket-release'):
    mmap = json.loads((package / 'validation/bpf-mmap-tests.json').read_text())
    assert mmap['asan_ubsan'] == 'passed' and all(r['passed'] for r in mmap['page_size_variants'].values())
    assert not mmap['device_tested'] and not mmap['real_vm_lifetime_tested']
    assert all(sha(kernel / name) == value for name, value in mmap['source_sha256'].items())
    record['host_mmap_cases'] = mmap['cases']
if native_prefix == 'bpf-socket-release':
    release = json.loads((package / 'validation/bpf-socket-release-tests.json').read_text())
    assert release['asan_ubsan'] == 'passed' and all(r['passed'] for r in release['variants'].values())
    assert release['pre_fix_context_pruning_regression_reproduced']
    assert not release['device_tested'] and not release['real_socket_concurrency_tested']
    assert not release['loaded_bpf_programs_tested']
    assert all(sha(kernel / name) == value for name, value in release['source_sha256'].items())
    record['host_release_cases'] = release['cases']
report_path.write_text(json.dumps(record, indent=2) + '\n')
print('Current BPF native/host/patch evidence matches installed sources; Image and runtime remain unverified.')
