#!/usr/bin/env python3
"""Add the standard socket-release hook after the four pinned BPF ports."""
from pathlib import Path
import difflib
import hashlib
import json
import re
import subprocess

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
record_path = package / 'validation/bpf-socket-release-source-port.json'
assert not record_path.exists(), 'Port already recorded; do not reapply'
subprocess.run(['python3', str(package / 'tools/apply-bpf-backports.py'), '--kernel', str(kernel)], check=True)
before, changes = {}, {}

def read(name):
    before[name] = (kernel / name).read_text()
    return before[name]

def replace(text, old, new):
    assert text.count(old) == 1, 'Missing/ambiguous anchor: ' + old[:100]
    return text.replace(old, new, 1)

def inside(text, name, transform):
    match = re.search(r'^(?:static\s+)?[^;{}\n]*\b' + name + r'\([^;{}]*?\)\s*\{', text, re.M)
    assert match, name
    start = text.index('{', match.start())
    end, depth = start + 1, 1
    while depth:
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        end += 1
    return text[:start] + transform(text[start:end]) + text[end:]

name = 'include/uapi/linux/bpf.h'
changes[name] = replace(read(name), '\tBPF_CGROUP_SETSOCKOPT,\n',
                       '\tBPF_CGROUP_SETSOCKOPT,\n\tBPF_CGROUP_INET_SOCK_RELEASE = 23,\n')

name = 'include/linux/bpf.h'
changes[name] = replace(read(name), '\tARG_ANYTHING,\t\t/* any (initialized) argument is ok */',
                       '\tARG_ANYTHING,\t\t/* any (initialized) argument is ok */\n'
                       '\tARG_PTR_TO_SOCK_CTX,\t/* unmodified CGROUP_SOCK context */')

name = 'include/linux/bpf-cgroup.h'
text = replace(read(name), 'int __cgroup_bpf_run_filter_sk(struct sock *sk,',
               'void __cgroup_bpf_run_sock_release(struct sock *sk);\n\n'
               'int __cgroup_bpf_run_filter_sk(struct sock *sk,')
anchor = '#define BPF_CGROUP_RUN_PROG_INET_SOCK(sk)'
at = text.index(anchor)
text = text[:at] + ('#define BPF_CGROUP_RUN_PROG_INET_SOCK_RELEASE(sk) \\\n'
    'do { \\\n\ttypeof(sk) __sk = (sk); \\\n'
    '\tif (cgroup_bpf_enabled && __sk) \\\n'
    '\t\t__cgroup_bpf_run_sock_release(__sk); \\\n} while (0)\n\n') + text[at:]
changes[name] = replace(text, '#define BPF_CGROUP_RUN_PROG_INET_SOCK(sk) ({ 0; })',
                       '#define BPF_CGROUP_RUN_PROG_INET_SOCK_RELEASE(sk) do { } while (0)\n'
                       '#define BPF_CGROUP_RUN_PROG_INET_SOCK(sk) ({ 0; })')

name = 'kernel/bpf/cgroup.c'
changes[name] = replace(read(name), 'EXPORT_SYMBOL(__cgroup_bpf_run_filter_sk);',
                       'EXPORT_SYMBOL(__cgroup_bpf_run_filter_sk);\n\n' +
                       (package / 'kernel-patches/release-cgroup.c').read_text())

name = 'kernel/bpf/syscall.c'
text = read(name)
for fn in ['bpf_prog_load_check_attach_type', 'bpf_prog_attach', 'bpf_prog_detach', 'bpf_prog_query']:
    text = inside(text, fn, lambda body: replace(body, 'case BPF_CGROUP_INET_SOCK_CREATE:',
                   'case BPF_CGROUP_INET_SOCK_CREATE:\n\tcase BPF_CGROUP_INET_SOCK_RELEASE:'))
changes[name] = text

name = 'net/core/filter.c'
text = replace(read(name), 'const struct bpf_verifier_ops cg_sock_verifier_ops = {',
               (package / 'kernel-patches/release-filter.c').read_text() + '\n\n'
               'const struct bpf_verifier_ops cg_sock_verifier_ops = {')
text = inside(text, 'sock_filter_is_valid_access', lambda body:
    replace(body, '{\n', '{\n\t/* Notification context is read-only; no legacy narrow-load rewriting. */\n'
            '\tif (prog->expected_attach_type == BPF_CGROUP_INET_SOCK_RELEASE) {\n'
            '\t\tif (type != BPF_READ || size != sizeof(__u32) ||\n'
            '\t\t    off < 0 || off > sizeof(struct bpf_sock) - sizeof(__u32) ||\n'
            '\t\t    (off & 3))\n\t\t\treturn false;\n'
            '\t\tbpf_ctx_record_field_size(info, sizeof(__u32));\n'
            '\t\treturn true;\n\t}\n\n'))
changes[name] = replace(text, '.get_func_proto\t\t= bpf_base_func_proto,\n\t.is_valid_access\t= sock_filter_is_valid_access,',
                       '.get_func_proto\t\t= cg_sock_func_proto,\n\t.is_valid_access\t= sock_filter_is_valid_access,')

name = 'kernel/bpf/verifier.c'
text = read(name)
guard = ('static bool bpf_sock_ctx_reg_is_unmodified(const struct bpf_reg_state *reg)\n{\n'
         '\treturn reg->type == PTR_TO_CTX && reg->off == 0 &&\n'
         '\t\ttnum_is_const(reg->var_off) && reg->var_off.value == 0 &&\n'
         '\t\treg->smin_value == 0 && reg->smax_value == 0 &&\n'
         '\t\treg->umin_value == 0 && reg->umax_value == 0;\n}\n\n')
text = replace(text, 'static bool bpf_sock_reg_is_unmodified(', guard + 'static bool bpf_sock_reg_is_unmodified(')
text = replace(text, '\t} else if (arg_type == ARG_PTR_TO_SOCKET) {',
               '\t} else if (arg_type == ARG_PTR_TO_SOCK_CTX) {\n'
               '\t\texpected_type = PTR_TO_CTX;\n'
               '\t\tif (type != expected_type)\n\t\t\tgoto err_type;\n'
               '\t\tif (!bpf_sock_ctx_reg_is_unmodified(reg))\n\t\t\treturn -EACCES;\n'
               '\t} else if (arg_type == ARG_PTR_TO_SOCKET) {')
text = replace(text, '\tif (rcur->type == PTR_TO_SOCKET && rold->type != PTR_TO_SOCKET)\n\t\treturn false;\n',
               '\tif (rcur->type == PTR_TO_SOCKET && rold->type != PTR_TO_SOCKET)\n\t\treturn false;\n'
               '\t/* A scalar path must not hide a socket context helper argument. */\n'
               '\tif (rcur->type == PTR_TO_CTX && rold->type != PTR_TO_CTX)\n\t\treturn false;\n')
changes[name] = text

name = 'net/ipv4/af_inet.c'
changes[name] = inside(read(name), 'inet_release', lambda body:
    replace(body, '\t\tlong timeout;\n', '\t\tlong timeout;\n\n'
            '\t\t/* Notify before detaching or closing the live socket. */\n'
            '\t\tBPF_CGROUP_RUN_PROG_INET_SOCK_RELEASE(sk);\n'))

# All anchors must succeed before modifying any kernel file.
backup = package / 'validation/bpf-socket-release-before'
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
patch_path = package / 'kernel-patches/0005-r24u-socket-release.patch'
patch_path.write_text(''.join(patch))
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
record = {'kernel_commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=kernel, text=True).strip(),
          'scope': 'INET socket release notification, shared IPv4/IPv6 path and correctly typed context helpers',
          'predecessor_patch_sha256': sha(package / 'kernel-patches/0004-r24u-array-mmap.patch'),
          'patch_sha256': sha(patch_path), 'before_sha256': {n: sha(backup / n) for n in changes},
          'changed_files': {n: sha(kernel / n) for n in changes},
          'unsupported': ['Acquired/nullable socket references', 'SK_STORAGE', 'RINGBUF', 'Complete Android17 BPF contract'],
          'affected_units_compile_passed': False, 'full_kernel_link_passed': False,
          'device_tested': False, 'android17_network_validated': False, 'installable_package': False}
record_path.write_text(json.dumps(record, indent=2) + '\n')
print('Socket-release hook installed in sources; unit compilation, helper guards and close-order tests pending.')
