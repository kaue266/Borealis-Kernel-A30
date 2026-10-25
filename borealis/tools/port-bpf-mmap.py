#!/usr/bin/env python3
"""Port real shared mmap for BPF arrays after the three existing BPF ports."""
from pathlib import Path
import difflib
import hashlib
import json
import re
import subprocess

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
record_path = package / 'validation/bpf-mmap-source-port.json'
assert not record_path.exists(), 'Port already recorded; inspect instead of reapplying'
subprocess.run(['python3', str(package / 'tools/apply-bpf-backports.py'), '--kernel', str(kernel)], check=True)
before, changes = {}, {}


def read(name):
    before[name] = (kernel / name).read_text()
    return before[name]


def replace(text, old, new):
    assert text.count(old) == 1, 'Missing/ambiguous anchor: ' + old[:120]
    return text.replace(old, new, 1)


def inside(text, name, transform):
    match = re.search(r'^static [^;{}\n]*\b' + name + r'\([^;{}]*?\)\s*\{', text, re.M)
    assert match, name
    start = text.index('{', match.start())
    end, depth = start + 1, 1
    while depth:
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        end += 1
    return text[:start] + transform(text[start:end]) + text[end:]


name = 'include/uapi/linux/bpf.h'
text = read(name)
assert 'BPF_F_MMAPABLE' not in text
changes[name] = replace(text, '#define BPF_F_WRONLY\t\t(1U << 4)',
                       '#define BPF_F_WRONLY\t\t(1U << 4)\n\n/* Array values may be shared through mmap. */\n'
                       '#define BPF_F_MMAPABLE\t\t(1U << 10)')

name = 'include/linux/bpf.h'
text = replace(read(name), 'struct bpf_map;\n', 'struct bpf_map;\nstruct vm_area_struct;\n')
text = replace(text, '\tvoid (*map_free)(struct bpf_map *map);',
               '\tvoid (*map_free)(struct bpf_map *map);\n'
               '\tint (*map_mmap)(struct bpf_map *map, struct vm_area_struct *vma);')
changes[name] = replace(text, 'void *bpf_map_area_alloc(size_t size, int numa_node);',
                       'void *bpf_map_area_alloc(size_t size, int numa_node);\n'
                       'void *bpf_map_area_mmapable_alloc(size_t size, int numa_node);')

name = 'kernel/bpf/arraymap.c'
text = replace(read(name), '#include <linux/mm.h>', '#include <linux/mm.h>\n#include <linux/vmalloc.h>')
text = replace(text, '(BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_WRONLY)',
               '(BPF_F_NUMA_NODE | BPF_F_RDONLY | BPF_F_WRONLY | BPF_F_MMAPABLE)')
text = replace(text, '/* Called from syscall */\nstatic struct bpf_map *array_map_alloc(',
               (package / 'kernel-patches/mmap-array.c').read_text() + '\n\n'
               '/* Called from syscall */\nstatic struct bpf_map *array_map_alloc(')
text = inside(text, 'array_map_alloc', lambda body:
    replace(body, '\tif (attr->value_size >= 1 << (KMALLOC_SHIFT_MAX - 1))',
            '\t/* FD/per-CPU arrays must never expose pointers through mmap. */\n'
            '\tif (attr->map_type != BPF_MAP_TYPE_ARRAY &&\n'
            '\t    (attr->map_flags & BPF_F_MMAPABLE))\n\t\treturn ERR_PTR(-EINVAL);\n\n'
            '\tif (attr->value_size >= 1 << (KMALLOC_SHIFT_MAX - 1))'))
text = inside(text, 'array_map_alloc', lambda body:
    replace(body, '\telse\n\t\tarray_size += (u64) max_entries * elem_size;',
            '\telse if (attr->map_flags & BPF_F_MMAPABLE)\n'
            '\t\tarray_size = PAGE_ALIGN(array_size) +\n'
            '\t\t\tPAGE_ALIGN((u64)max_entries * elem_size);\n'
            '\telse\n\t\tarray_size += (u64) max_entries * elem_size;'))
text = inside(text, 'array_map_alloc', lambda body:
    replace(body, '\tarray = bpf_map_area_alloc(array_size, numa_node);',
            '\tif (attr->map_flags & BPF_F_MMAPABLE) {\n'
            '\t\tvoid *data = bpf_map_area_mmapable_alloc(array_size, numa_node);\n'
            '\t\tif (!data)\n\t\t\treturn ERR_PTR(-ENOMEM);\n'
            '\t\tarray = (struct bpf_array *)((char *)data + PAGE_ALIGN(sizeof(*array)) -\n'
            '\t\t\toffsetof(struct bpf_array, value));\n'
            '\t} else {\n\t\tarray = bpf_map_area_alloc(array_size, numa_node);\n\t}'))
text = inside(text, 'array_map_free', lambda body:
    replace(body, '\tbpf_map_area_free(array);',
            '\tif (map->map_flags & BPF_F_MMAPABLE)\n'
            '\t\tvfree(array_map_vmalloc_addr(array));\n'
            '\telse\n\t\tbpf_map_area_free(array);'))
changes[name] = replace(text, 'const struct bpf_map_ops array_map_ops = {',
                        'const struct bpf_map_ops array_map_ops = {\n\t.map_mmap = array_map_mmap,')

name = 'kernel/bpf/syscall.c'
text = replace(read(name), '#include <linux/mmzone.h>', '#include <linux/mmzone.h>\n#include <linux/mm.h>')
text = replace(text, 'const struct file_operations bpf_map_fops = {',
               (package / 'kernel-patches/mmap-syscall.c').read_text() + '\n\n'
               'const struct file_operations bpf_map_fops = {\n\t.mmap\t\t= bpf_map_mmap,')
changes[name] = text

# Validate every replacement before modifying any kernel file.
backup = package / 'validation/bpf-mmap-before'
patch = []
for name, after in changes.items():
    assert not (backup / name).exists()
    patch.extend(difflib.unified_diff(before[name].splitlines(True), after.splitlines(True),
                                    fromfile='a/' + name, tofile='b/' + name))
for name, after in changes.items():
    target = backup / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(before[name])
    (kernel / name).write_text(after)
patch_path = package / 'kernel-patches/0004-r24u-array-mmap.patch'
patch_path.write_text(''.join(patch))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
record = {'kernel_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=kernel, text=True).strip(),
          'scope': 'Shared zero-initialized array values; metadata pages excluded from mmap',
          'predecessor_patch_sha256': sha(package / 'kernel-patches/0003-r24u-borrowed-socket.patch'),
          'patch_sha256': sha(patch_path), 'before_sha256': {n: sha(backup / n) for n in changes},
          'changed_files': {n: sha(kernel / n) for n in changes},
          'unsupported': ['Per-CPU/FD arrays and other map types', 'MAP_FREEZE',
                          'BTF spin-lock values and program-readonly map flags'],
          'affected_units_compile_passed': False, 'full_kernel_link_passed': False,
          'device_tested': False, 'android17_network_validated': False, 'installable_package': False}
record_path.write_text(json.dumps(record, indent=2) + '\n')
print('Array mmap port installed in sources; native, bounds and lifetime checks pending.')
