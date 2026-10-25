#!/usr/bin/env python3
"""Backport real MADV_WIPEONFORK semantics to the recorded R24U kernel."""
import difflib
import hashlib
import json
from pathlib import Path
import subprocess
import time
import urllib.request

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
reports = package / 'validation/kernel'
record_path = reports / 'wipeonfork-backport.json'
patch_path = package / 'kernel-patches/0006-r24u-wipeonfork.patch'
if record_path.exists():
    record = json.loads(record_path.read_text())
    for name, digest in record['after_sha256'].items():
        assert hashlib.sha256((kernel / name).read_bytes()).hexdigest() == digest, name
    assert hashlib.sha256(patch_path.read_bytes()).hexdigest() == record['patch_sha256']
    print('MADV_WIPEONFORK source matches its recorded backport.')
    raise SystemExit(0)
for proc in Path('/proc').iterdir():
    if not proc.name.isdigit():
        continue
    try:
        assert proc.joinpath('comm').read_text().strip() not in (
            'clang', 'clang++', 'make', 'ld.lld', 'soong_ui', 'soong_build', 'siso', 'ninja')
    except FileNotFoundError:
        pass
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=kernel, text=True).strip() == \
       'e1b8464bb29ce5bcb9d52bfcfc71bc2563e12563'
upstream = {}
upstream_dir = reports / 'wipeonfork-upstream'
upstream_dir.mkdir(parents=True, exist_ok=True)
for commit in ('d2cd9ede6e193dd7d88b6d27399e96229a551b19',
               '93949bb21b52aae924fd26f9775c8655dd9e885e'):
    url = f'https://github.com/torvalds/linux/commit/{commit}.patch'
    raw = urllib.request.urlopen(url, timeout=30).read()
    assert raw.startswith(f'From {commit} '.encode())
    (upstream_dir / (commit + '.patch')).write_bytes(raw)
    upstream[commit] = {'url': url, 'sha256': hashlib.sha256(raw).hexdigest()}

before = {}
after = {}
def replace(name, old, new):
    if name not in before:
        before[name] = (kernel / name).read_text()
        after[name] = before[name]
    assert after[name].count(old) == 1, (name, old)
    after[name] = after[name].replace(old, new, 1)

# Internal VMA bit 0x00800000 is free in this 4.4 tree. Keep VM_ARCH_2/VM_MPX
# intact instead of taking their bit, as newer upstream kernels could do.
assert '0x00800000' not in (kernel / 'include/linux/mm.h').read_text()
replace('include/linux/mm.h', '#define VM_ARCH_1\t0x01000000',
        '#define VM_WIPEONFORK\t0x00800000\t/* Zero this VMA in fork children. */\n'
        '#define VM_ARCH_1\t0x01000000')
for name, wipe, keep in (
    ('include/uapi/asm-generic/mman-common.h', 18, 19),
    ('arch/alpha/include/uapi/asm/mman.h', 18, 19),
    ('arch/mips/include/uapi/asm/mman.h', 18, 19),
    ('arch/parisc/include/uapi/asm/mman.h', 71, 72),
    ('arch/xtensa/include/uapi/asm/mman.h', 18, 19),
):
    data = (kernel / name).read_text()
    line = next(s for s in data.splitlines(keepends=True) if s.startswith('#define MADV_DODUMP'))
    replace(name, line, line +
            f'#define MADV_WIPEONFORK {wipe}\t/* Zero memory on fork, child only */\n'
            f'#define MADV_KEEPONFORK {keep}\t/* Undo MADV_WIPEONFORK */\n')
replace('mm/madvise.c', '\tcase MADV_DONTDUMP:\n\t\tnew_flags |= VM_DONTDUMP;',
        '\tcase MADV_WIPEONFORK:\n'
        '\t\t/* Only private anonymous mappings can be wiped on fork. */\n'
        '\t\tif (vma->vm_file || (vma->vm_flags & VM_SHARED)) {\n'
        '\t\t\terror = -EINVAL;\n'
        '\t\t\tgoto out;\n'
        '\t\t}\n'
        '\t\tnew_flags |= VM_WIPEONFORK;\n'
        '\t\tbreak;\n'
        '\tcase MADV_KEEPONFORK:\n'
        '\t\tnew_flags &= ~VM_WIPEONFORK;\n'
        '\t\tbreak;\n'
        '\tcase MADV_DONTDUMP:\n\t\tnew_flags |= VM_DONTDUMP;')
# madvise_behavior_valid has a second DONTDUMP; use its exact pair as anchor.
replace('mm/madvise.c', '\tcase MADV_DODUMP:\n\t\treturn true;',
        '\tcase MADV_DODUMP:\n\tcase MADV_WIPEONFORK:\n'
        '\tcase MADV_KEEPONFORK:\n\t\treturn true;')
replace('kernel/fork.c', '\t\tif (anon_vma_fork(tmp, mpnt))\n',
        '\t\tif (tmp->vm_flags & VM_WIPEONFORK) {\n'
        '\t\t\t/* No inherited pages or parent anon_vma; prepare on fault. */\n'
        '\t\t\ttmp->anon_vma = NULL;\n'
        '\t\t} else if (anon_vma_fork(tmp, mpnt))\n')
replace('kernel/fork.c', '\t\tretval = copy_page_range(mm, oldmm, mpnt);\n',
        '\t\tif (!(tmp->vm_flags & VM_WIPEONFORK))\n'
        '\t\t\tretval = copy_page_range(mm, oldmm, mpnt);\n')
replace('fs/proc/task_mmu.c', '\t\t[ilog2(VM_DONTDUMP)]\t= "dd",\n',
        '\t\t[ilog2(VM_WIPEONFORK)]\t= "wf",\n'
        '\t\t[ilog2(VM_DONTDUMP)]\t= "dd",\n')

patch = ''.join(''.join(difflib.unified_diff(before[name].splitlines(keepends=True),
                        after[name].splitlines(keepends=True),
                        fromfile='a/'+name, tofile='b/'+name)) for name in sorted(before))
patch_path.write_text(patch)
subprocess.run(['git', 'apply', '--check', str(patch_path)], cwd=kernel, check=True)
subprocess.run(['git', 'apply', str(patch_path)], cwd=kernel, check=True)
record = {
    'timestamp_utc': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
    'upstream': upstream,
    'kernel_commit': 'e1b8464bb29ce5bcb9d52bfcfc71bc2563e12563',
    'before_sha256': {n: hashlib.sha256(v.encode()).hexdigest() for n,v in before.items()},
    'after_sha256': {n: hashlib.sha256(v.encode()).hexdigest() for n,v in after.items()},
    'patch_sha256': hashlib.sha256(patch.encode()).hexdigest(),
    'internal_vm_flag': '0x00800000 (free in R24U; existing MPX bit preserved)',
    'private_anonymous_only': True,
    'child_page_table_inheritance_skipped': True,
    'parent_anon_vma_not_inherited': True,
    'secure_fork_semantics_implemented': True,
    'full_kernel_link_passed': False,
    'device_semantics_test_passed': False,
    'bootloop_causality_proved': False,
    'android17_bpf_requirements_bypassed': False,
    'selinux_enforcing_preserved': True,
    'thermal_protections_modified': False,
    'flash_performed': False,
}
record_path.write_text(json.dumps(record, indent=2)+'\n')
print(json.dumps(record))
