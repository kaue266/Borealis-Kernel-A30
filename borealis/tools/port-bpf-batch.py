#!/usr/bin/env python3
"""Install two real R24U batch lookup APIs, after the socket-option port."""
from pathlib import Path
import difflib
import hashlib
import json
import subprocess

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=kernel, text=True).strip()
assert commit == 'e1b8464bb29ce5bcb9d52bfcfc71bc2563e12563'
record_path = package / 'validation/bpf-batch-source-port.json'
assert not record_path.exists(), 'Port already recorded; inspect rather than reapply'
sockopt = json.loads((package / 'validation/bpf-sockopt-source-port.json').read_text())
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert all(sha(kernel / n) == h for n, h in sockopt['changed_files'].items())
before, changes = {}, {}


def read(name):
    before[name] = (kernel / name).read_text()
    return before[name]


def replace(text, old, new):
    assert text.count(old) == 1, 'Missing/ambiguous anchor: ' + old[:90]
    return text.replace(old, new, 1)


name = 'include/uapi/linux/bpf.h'
text = replace(read(name), '\tBPF_BTF_LOAD = 18,',
               '\tBPF_BTF_LOAD = 18,\n\tBPF_MAP_LOOKUP_BATCH = 24,\n\tBPF_MAP_LOOKUP_AND_DELETE_BATCH = 25,')
batch = '''
    struct { /* Standard batch lookup ABI; pointers aligned on ARM32 too. */
        __aligned_u64 in_batch;
        __aligned_u64 out_batch;
        __aligned_u64 keys;
        __aligned_u64 values;
        __u32 count;
        __u32 map_fd;
        __u64 elem_flags;
        __u64 flags;
    } batch;

'''
changes[name] = replace(text, 'union bpf_attr {', 'union bpf_attr {\n' + batch)
name = 'include/linux/bpf.h'
ops = '''
    int (*map_lookup_batch)(struct bpf_map *map, const union bpf_attr *attr,
                           union bpf_attr __user *uattr);
    int (*map_lookup_and_delete_batch)(struct bpf_map *map, const union bpf_attr *attr,
                                      union bpf_attr __user *uattr);
'''
text = replace(read(name), '\t/* funcs callable from userspace and from eBPF programs */',
               ops + '\n\t/* funcs callable from userspace and from eBPF programs */')
prototype = '''
int bpf_array_lookup_batch(struct bpf_map *map, const union bpf_attr *attr,
                          union bpf_attr __user *uattr);
'''
changes[name] = replace(text, 'struct bpf_map {', prototype + '\nstruct bpf_map {')
name = 'kernel/bpf/hashtab.c'
text = replace(read(name), 'const struct bpf_map_ops htab_map_ops = {',
               (package / 'kernel-patches/batch-htab.c').read_text() + '\nconst struct bpf_map_ops htab_map_ops = {')
for kind in ['htab', 'htab_lru', 'htab_percpu', 'htab_lru_percpu']:
    anchor = 'const struct bpf_map_ops ' + kind + '_map_ops = {'
    text = replace(text, anchor, anchor + '\n\t.map_lookup_batch = htab_map_lookup_batch,\n'
                   '\t.map_lookup_and_delete_batch = htab_map_lookup_and_delete_batch,')
changes[name] = text
name = 'kernel/bpf/arraymap.c'
text = read(name)
for kind in ['array', 'percpu_array']:
    anchor = 'const struct bpf_map_ops ' + kind + '_map_ops = {'
    text = replace(text, anchor, anchor + '\n\t.map_lookup_batch = bpf_array_lookup_batch,')
changes[name] = text
name = 'kernel/bpf/syscall.c'
text = replace(read(name), 'SYSCALL_DEFINE3(bpf, int, cmd,',
    (package / 'kernel-patches/batch-array.c').read_text() + '\n' +
    (package / 'kernel-patches/batch-syscall.c').read_text() + '\nSYSCALL_DEFINE3(bpf, int, cmd,')
text = replace(text, '\tcase BPF_BTF_LOAD:\n\t\terr = bpf_btf_load(&attr);',
    '\tcase BPF_MAP_LOOKUP_BATCH:\n\tcase BPF_MAP_LOOKUP_AND_DELETE_BATCH:\n'
    '\t\terr = bpf_map_do_batch(&attr, uattr, cmd);\n\t\tbreak;\n'
    '\tcase BPF_BTF_LOAD:\n\t\terr = bpf_btf_load(&attr);')
changes[name] = text
# Prevalidate all anchors before any write and preserve the exact predecessor.
backup = package / 'validation/bpf-batch-before'
patch = []
for name, after in changes.items():
    target = backup / name
    assert not target.exists()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(before[name])
    patch.extend(difflib.unified_diff(before[name].splitlines(True), after.splitlines(True),
                 fromfile='a/' + name, tofile='b/' + name))
(package / 'kernel-patches/0002-r24u-map-batch.patch').write_text(''.join(patch))
for name, after in changes.items():
    (kernel / name).write_text(after)
record = {'kernel_commit': commit, 'scope': 'Batch lookup APIs for hash/percpu/LRU hash and arrays',
          'predecessor_patch_sha256': sockopt['patch_sha256'],
          'before_sha256': {n: sha(backup / n) for n in changes},
          'changed_files': {n: sha(kernel / n) for n in changes},
          'unsupported': ['Nonzero flags, including BPF_F_LOCK',
                          'Batch updates/deletes without lookup', 'Batch lookup for other map types'],
          'affected_units_compile_passed': False, 'full_kernel_link_passed': False,
          'runtime_tested': False, 'android17_network_validated': False, 'installable_package': False}
record_path.write_text(json.dumps(record, indent=2) + '\n')
print('R24U batch lookup source installed; native and behavior checks pending.')
