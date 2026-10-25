#!/usr/bin/env python3
"""Install a checked R24U socket-option backport; do not bypass Android gates."""
from pathlib import Path
import difflib
import hashlib
import json
import re
import subprocess

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
assert subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=kernel, text=True).strip() == 'e1b8464bb29ce5bcb9d52bfcfc71bc2563e12563'
report_path = package / 'validation/bpf-sockopt-source-port.json'
assert not report_path.exists(), 'Port already recorded; inspect current changes rather than reapplying'
changes = {}
before = {}


def read(name):
    value = (kernel / name).read_text()
    before[name] = value
    return value


def replace(text, old, new):
    assert text.count(old) == 1, 'Missing or ambiguous anchor: ' + old[:100]
    return text.replace(old, new, 1)


def body_span(text, pattern):
    match = re.search(pattern, text)
    assert match, 'Missing function/macro: ' + pattern
    start = text.index('{', match.start())
    depth = 1
    # These selected bodies contain no braces inside string literals/comments.
    end = start + 1
    while depth:
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        end += 1
    return start, end


def in_function(text, name, transform):
    start, end = body_span(text, r'\b' + name + r'\([^;]*?\)\s*\{')
    return text[:start] + transform(text[start:end]) + text[end:]


name = 'include/uapi/linux/bpf.h'
text = read(name)
text = replace(text, '\tBPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,',
               '\tBPF_PROG_TYPE_CGROUP_SOCK_ADDR = 18,\n\tBPF_PROG_TYPE_CGROUP_SOCKOPT = 25,')
text = replace(text, '\t__MAX_BPF_ATTACH_TYPE',
               '\tBPF_CGROUP_GETSOCKOPT = 21,\n\tBPF_CGROUP_SETSOCKOPT,\n\t__MAX_BPF_ATTACH_TYPE')
uapi = '''
/* Socket-option context uses the standard 64-bit-aligned BPF pointer ABI. */
#define __bpf_md_ptr(type, name) \\
union { type name; __u64 :64; } __attribute__((aligned(8)))

struct bpf_sockopt {
    __bpf_md_ptr(struct bpf_sock *, sk);
    __bpf_md_ptr(void *, optval);
    __bpf_md_ptr(void *, optval_end);
    __s32 level;
    __s32 optname;
    __s32 optlen;
    __s32 retval;
};

'''
text = replace(text, '#endif /* _UAPI__LINUX_BPF_H__ */', uapi + '#endif /* _UAPI__LINUX_BPF_H__ */')
changes[name] = text

name = 'include/linux/filter.h'
text = read(name)
context = '''
struct bpf_sockopt_kern {
    struct sock *sk;
    u8 *optval;
    u8 *optval_end;
    s32 level;
    s32 optname;
    s32 optlen;
    s32 retval;
};

'''
changes[name] = replace(text, '#endif /* __LINUX_FILTER_H__ */', context + '#endif /* __LINUX_FILTER_H__ */')

name = 'include/linux/bpf.h'
text = read(name)
changes[name] = replace(text, 'int bpf_prog_array_length(struct bpf_prog_array __rcu *progs);',
    'int bpf_prog_array_length(struct bpf_prog_array __rcu *progs);\nbool bpf_prog_array_is_empty(struct bpf_prog_array *progs);')

name = 'include/linux/bpf_types.h'
text = read(name)
changes[name] = replace(text, 'BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, cg_sock_addr)',
    'BPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCK_ADDR, cg_sock_addr)\n#ifdef CONFIG_CGROUP_BPF\nBPF_PROG_TYPE(BPF_PROG_TYPE_CGROUP_SOCKOPT, cg_sockopt)\n#endif')

name = 'kernel/bpf/Makefile'
text = read(name)
changes[name] = replace(text, 'obj-$(CONFIG_CGROUP_BPF) += cgroup.o',
    'obj-$(CONFIG_CGROUP_BPF) += cgroup.o\nifeq ($(CONFIG_NET),y)\nobj-$(CONFIG_CGROUP_BPF) += sockopt.o\nendif')

name = 'kernel/bpf/core.c'
text = read(name)
empty = '''
bool bpf_prog_array_is_empty(struct bpf_prog_array *progs)
{
    struct bpf_prog **entry;
    struct bpf_prog *prog;

    if (!progs)
        return true;
    for (entry = progs->progs; (prog = READ_ONCE(*entry)); entry++)
        if (prog != &dummy_bpf_prog.prog)
            return false;
    return true;
}

'''
changes[name] = replace(text, 'void bpf_prog_array_delete_safe(', empty + 'void bpf_prog_array_delete_safe(')

name = 'include/linux/bpf-cgroup.h'
text = read(name)
hooks = r'''
int __cgroup_bpf_run_filter_setsockopt(struct sock *sk, int *level,
        int *optname, char __user *optval, int *optlen, char **kernel_optval);
int __cgroup_bpf_run_filter_getsockopt(struct sock *sk, int level,
        int optname, char __user *optval, int __user *optlen,
        int max_optlen, int retval);

#define BPF_CGROUP_RUN_PROG_SETSOCKOPT(sk, level, name, value, length, kvalue) \
    __cgroup_bpf_run_filter_setsockopt(sk, level, name, value, length, kvalue)
#define BPF_CGROUP_RUN_PROG_GETSOCKOPT(sk, level, name, value, length, maxlen, ret) \
    __cgroup_bpf_run_filter_getsockopt(sk, level, name, value, length, maxlen, ret)
#define BPF_CGROUP_GETSOCKOPT_MAX_OPTLEN(length) \
({ int __length = 0; if (cgroup_bpf_enabled) get_user(__length, length); __length; })

'''
text = replace(text, '#else\n\nstruct cgroup_bpf {};', hooks + '#else\n\nstruct cgroup_bpf {};')
fallback = r'''
#define BPF_CGROUP_RUN_PROG_SETSOCKOPT(sk, level, name, value, length, kvalue) (0)
#define BPF_CGROUP_RUN_PROG_GETSOCKOPT(sk, level, name, value, length, maxlen, ret) (ret)
#define BPF_CGROUP_GETSOCKOPT_MAX_OPTLEN(length) (0)
'''
changes[name] = replace(text, '#endif /* CONFIG_CGROUP_BPF */', fallback + '\n#endif /* CONFIG_CGROUP_BPF */')

name = 'kernel/bpf/syscall.c'
text = read(name)
load_check = '''\tcase BPF_PROG_TYPE_CGROUP_SOCKOPT:
        return expected_attach_type == BPF_CGROUP_GETSOCKOPT ||
               expected_attach_type == BPF_CGROUP_SETSOCKOPT ? 0 : -EINVAL;
'''
text = in_function(text, 'bpf_prog_load_check_attach_type', lambda body:
    replace(body, '\tdefault:\n\t\treturn 0;', load_check + '\tdefault:\n\t\treturn 0;'))
text = in_function(text, 'bpf_prog_attach_check_attach_type', lambda body:
    replace(body, '\tcase BPF_PROG_TYPE_CGROUP_SOCK_ADDR:',
            '\tcase BPF_PROG_TYPE_CGROUP_SOCK_ADDR:\n\tcase BPF_PROG_TYPE_CGROUP_SOCKOPT:'))
attach = '''\tcase BPF_CGROUP_GETSOCKOPT:
\tcase BPF_CGROUP_SETSOCKOPT:
        ptype = BPF_PROG_TYPE_CGROUP_SOCKOPT;
        break;
'''
for function in ('bpf_prog_attach', 'bpf_prog_detach'):
    text = in_function(text, function, lambda body:
        replace(body, '\tcase BPF_CGROUP_DEVICE:', attach + '\tcase BPF_CGROUP_DEVICE:'))
text = in_function(text, 'bpf_prog_query', lambda body:
    replace(body, '\tcase BPF_CGROUP_DEVICE:',
        '\tcase BPF_CGROUP_GETSOCKOPT:\n\tcase BPF_CGROUP_SETSOCKOPT:\n\tcase BPF_CGROUP_DEVICE:'))
changes[name] = text

name = 'kernel/bpf/verifier.c'
text = read(name)
direct = '''\tcase BPF_PROG_TYPE_CGROUP_SOCKOPT:
        if (t == BPF_WRITE)
            env->seen_direct_write = true;
        return true;
'''
text = in_function(text, 'may_access_direct_pkt_data', lambda body:
    replace(body, '\tdefault:\n\t\treturn false;', direct + '\tdefault:\n\t\treturn false;'))
text = in_function(text, 'check_return_code', lambda body:
    replace(body, '\tcase BPF_PROG_TYPE_CGROUP_DEVICE:',
        '\tcase BPF_PROG_TYPE_CGROUP_SOCKOPT:\n\tcase BPF_PROG_TYPE_CGROUP_DEVICE:'))
changes[name] = text


def socket_body(body, operation, compat):
    if operation == 'setsockopt':
        declarations = '\n\tmm_segment_t oldfs = get_fs();\n\tchar *kernel_optval = NULL;'
        if compat:
            declarations += '\n\tint filtered_optlen;'
        assert body.startswith('{\n')
        body = '{' + declarations + body[1:]
        invocation = '''
        err = BPF_CGROUP_RUN_PROG_SETSOCKOPT(sock->sk, &level, &optname,
                optval, OPTLEN_POINTER, &kernel_optval);
        if (err < 0)
            goto borealis_sockopt_put;
        if (err > 0) {
            err = 0;
            goto borealis_sockopt_put;
        }
        if (kernel_optval) {
            set_fs(KERNEL_DS);
            optval = (char __user __force *)kernel_optval;
        }
'''
        invocation = invocation.replace('OPTLEN_POINTER', '&filtered_optlen' if compat else '&optlen')
        if compat:
            invocation = '''
        filtered_optlen = (int)optlen;
        if (filtered_optlen < 0) {
            err = -EINVAL;
            goto borealis_sockopt_put;
        }
''' + invocation + '\n        optlen = filtered_optlen;\n'
        body = replace(body, '\n\t\tif (level == SOL_SOCKET)', invocation + '\n\t\tif (level == SOL_SOCKET)')
        cleanup = '''
borealis_sockopt_put:
        if (kernel_optval) {
            set_fs(oldfs);
            kfree(kernel_optval);
        }
'''
        if compat:
            # The first sockfd_put is the pre-hook LSM error path; retain it.
            at = body.rindex('\n\t\tsockfd_put(sock);')
            body = body[:at] + cleanup + body[at:]
        else:
            body = replace(body, '\nout_put:', cleanup + '\nout_put:')
    else:
        assert body.startswith('{\n')
        body = '{\n\tint max_optlen;' + body[1:]
        body = replace(body, '\n\t\tif (level == SOL_SOCKET)',
            '\n        max_optlen = BPF_CGROUP_GETSOCKOPT_MAX_OPTLEN(optlen);\n\t\tif (level == SOL_SOCKET)')
        invocation = '''
        err = BPF_CGROUP_RUN_PROG_GETSOCKOPT(sock->sk, level, optname,
                optval, optlen, max_optlen, err);
'''
        if compat:
            at = body.rindex('\n\t\tsockfd_put(sock);')
            body = body[:at] + invocation + body[at:]
        else:
            body = replace(body, '\nout_put:', invocation + '\nout_put:')
    return body


for name, macro, compat in [('net/socket.c', 'SYSCALL_DEFINE5', False),
                            ('net/compat.c', 'COMPAT_SYSCALL_DEFINE5', True)]:
    text = read(name)
    if '#include <linux/bpf-cgroup.h>' not in text:
        include_at = text.index('#include ')
        text = text[:include_at] + '#include <linux/bpf-cgroup.h>\n' + text[include_at:]
    for operation in ('setsockopt', 'getsockopt'):
        start, end = body_span(text, macro + r'\(\s*' + operation + ',')
        text = text[:start] + socket_body(text[start:end], operation, compat) + text[end:]
    changes[name] = text

name = 'kernel/bpf/sockopt.c'
assert not (kernel / name).exists(), 'Unexpected existing sockopt source'
before[name] = ''
changes[name] = (package / 'kernel-patches/sockopt.c').read_text()
assert 'PTR_TO_SOCKET;' not in changes[name]

# All anchors have passed before changing any source. Preserve the baseline
# and a reviewable unified diff including the new compilation unit.
backup = package / 'validation/bpf-sockopt-before'
patch = []
for name, after in changes.items():
    target = backup / name
    assert not target.exists()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(before[name])
    patch.extend(difflib.unified_diff(before[name].splitlines(True), after.splitlines(True),
                 fromfile='a/' + name if before[name] else '/dev/null', tofile='b/' + name))
(package / 'kernel-patches/0001-r24u-cgroup-sockopt.patch').write_text(''.join(patch))
for name, after in changes.items():
    (kernel / name).write_text(after)
report = {'scope': 'First socket-option backport for R24U; full Android 17 compatibility not achieved',
          'changed_files': {name: hashlib.sha256(data.encode()).hexdigest() for name, data in changes.items()},
          'kernel_version_changed': False, 'aosp_loader_modified': False,
          'native_compile_passed': False, 'device_tested': False, 'installable_package': False,
          'unresolved': ['PTR_TO_SOCKET verifier and socket-storage helpers',
                         'Additional Android 17 BPF helpers and map batch APIs',
                         'AOSP loader compatibility gates and full networking runtime',
                         'Compiled kernel pair, boot and physical hardware proof']}
report_path.write_text(json.dumps(report, indent=2) + '\n')
print('Installed R24U socket-option source backport; compilation/runtime verification pending.')
