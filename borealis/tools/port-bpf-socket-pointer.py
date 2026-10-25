#!/usr/bin/env python3
"""Port borrowed socket typing, metadata translation and cookie helper."""
from pathlib import Path
import difflib
import hashlib
import json
import re
import subprocess

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
record_path = package / 'validation/bpf-socket-pointer-source-port.json'
assert not record_path.exists(), 'Port already recorded; inspect rather than reapply'
subprocess.run(['python3', str(package / 'tools/apply-bpf-backports.py'), '--kernel', str(kernel)], check=True)
commit = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=kernel, text=True).strip()
before, changes = {}, {}


def read(name):
    before[name] = (kernel / name).read_text()
    return before[name]


def replace(text, old, new):
    assert text.count(old) == 1, 'Missing/ambiguous anchor: ' + old[:120]
    return text.replace(old, new, 1)


def function_span(text, name):
    # Anchor to a declaration: mentions in comments must never select another
    # function's body while scanning forward through parentheses.
    match = re.search(r'^[ \t]*(?:static[ \t]+)?(?:int|bool|u32)[ \t]+' +
                      name + r'\([^;{}]*?\)\s*\{', text, re.M)
    assert match, name
    start = text.index('{', match.start())
    end, depth = start + 1, 1
    while depth:
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        end += 1
    return start, end


def inside(text, name, transform):
    start, end = function_span(text, name)
    return text[:start] + transform(text[start:end]) + text[end:]


name = 'include/uapi/linux/bpf.h'
text = read(name)
# The existing prefix keeps its ABI. Append real translated socket metadata.
match = re.search(r'struct bpf_sock \{.*?\n\};', text, re.S)
assert match
socket = match.group()
assert socket.endswith('\n};')
socket = socket[:-3] + '''
    __u32 dst_port; /* Network byte order in the lower 16 bits. */
    __u32 dst_ip4;
    __u32 dst_ip6[4];
    __u32 state;
    __s32 rx_queue_mapping; /* -1 means unavailable. */
};'''
changes[name] = text[:match.start()] + socket + text[match.end():]

name = 'include/linux/bpf.h'
text = replace(read(name), '\tARG_PTR_TO_CTX,\t\t/* pointer to context */',
               '\tARG_PTR_TO_CTX,\t\t/* pointer to context */\n\tARG_PTR_TO_SOCKET,\t/* unmodified borrowed socket */')
text = replace(text, '\tPTR_TO_PACKET_END,\t /* skb->data + headlen */',
               '\tPTR_TO_PACKET_END,\t /* skb->data + headlen */\n\tPTR_TO_SOCKET,\t\t /* borrowed live socket from a holding context */')
prototypes = '''
#ifdef CONFIG_NET
bool bpf_sock_is_valid_access(int off, int size, enum bpf_access_type type,
                             struct bpf_insn_access_aux *info);
u32 bpf_sock_convert_ctx_access(enum bpf_access_type type,
        const struct bpf_insn *si, struct bpf_insn *buffer,
        struct bpf_prog *prog, u32 *target_size);
#else
static inline bool bpf_sock_is_valid_access(int off, int size,
        enum bpf_access_type type, struct bpf_insn_access_aux *info)
{
    return false;
}
static inline u32 bpf_sock_convert_ctx_access(enum bpf_access_type type,
        const struct bpf_insn *si, struct bpf_insn *buffer,
        struct bpf_prog *prog, u32 *target_size)
{
    return 0;
}
#endif
extern const struct bpf_func_proto bpf_get_socket_cookie_sock_proto;
'''
changes[name] = replace(text, 'extern const struct bpf_func_proto bpf_map_lookup_elem_proto;',
                        prototypes + '\nextern const struct bpf_func_proto bpf_map_lookup_elem_proto;')

name = 'net/core/filter.c'
text = read(name)
text = replace(text, 'static bool sock_filter_is_valid_access(',
               (package / 'kernel-patches/socket-readonly.c').read_text() + '\nstatic bool sock_filter_is_valid_access(')
text = replace(text, 'static u32 sock_filter_convert_ctx_access(', 'u32 bpf_sock_convert_ctx_access(')
text, count = re.subn(r'(\.convert_ctx_access\s*=\s*)sock_filter_convert_ctx_access(,)',
                     r'\1bpf_sock_convert_ctx_access\2', text)
assert count == 1, 'Unexpected number of socket context converter registrations'
assert 'sock_filter_convert_ctx_access' not in text
text = inside(text, 'bpf_sock_convert_ctx_access', lambda body:
               replace(body, '\tint off;\n', '\tint off;\n\n\t*target_size = 4;\n'))
extra_fields = '''
    case offsetof(struct bpf_sock, dst_port):
        *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sock_common, skc_dport),
            si->dst_reg, si->src_reg,
            bpf_target_off(struct sock_common, skc_dport,
                FIELD_SIZEOF(struct sock_common, skc_dport), target_size));
        break;
    case offsetof(struct bpf_sock, dst_ip4):
        *insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
            offsetof(struct sock_common, skc_daddr));
        break;
    case bpf_ctx_range_till(struct bpf_sock, dst_ip6[0], dst_ip6[3]):
#if IS_ENABLED(CONFIG_IPV6)
        off = si->off - offsetof(struct bpf_sock, dst_ip6[0]);
        *insn++ = BPF_LDX_MEM(BPF_W, si->dst_reg, si->src_reg,
            offsetof(struct sock_common, skc_v6_daddr.s6_addr32[0]) + off);
#else
        *insn++ = BPF_MOV32_IMM(si->dst_reg, 0);
#endif
        break;
    case offsetof(struct bpf_sock, state):
        *insn++ = BPF_LDX_MEM(BPF_FIELD_SIZEOF(struct sock_common, skc_state),
            si->dst_reg, si->src_reg,
            bpf_target_off(struct sock_common, skc_state,
                FIELD_SIZEOF(struct sock_common, skc_state), target_size));
        break;
    case offsetof(struct bpf_sock, rx_queue_mapping):
        /* R24U does not expose sk_rx_queue_mapping. Return its documented
         * unavailable value, with the 32-bit load's correct zero extension.
         */
        *insn++ = BPF_MOV32_IMM(si->dst_reg, -1);
        break;
'''
text = inside(text, 'bpf_sock_convert_ctx_access', lambda body:
               replace(body, '\n\t}\n\n\treturn insn - insn_buf;', extra_fields + '\n\t}\n\n\treturn insn - insn_buf;'))
cookie = '''
BPF_CALL_1(bpf_get_socket_cookie_sock, struct sock *, sk)
{
    return sock_gen_cookie(sk);
}

const struct bpf_func_proto bpf_get_socket_cookie_sock_proto = {
    .func = bpf_get_socket_cookie_sock,
    .gpl_only = false,
    .ret_type = RET_INTEGER,
    .arg1_type = ARG_PTR_TO_SOCKET,
};

'''
changes[name] = replace(text, 'BPF_CALL_1(bpf_get_socket_uid,', cookie + 'BPF_CALL_1(bpf_get_socket_uid,')

name = 'kernel/bpf/sockopt.c'
text = read(name)
text = replace(text, 'Context validation rejects unsupported socket-pointer access; adding an\n * enum alone must never grant unchecked access to kernel memory.',
               'Socket pointers are borrowed from the holding hook context and validated\n * by the shared socket verifier; nullable/acquired sockets remain unsupported.')
text = replace(text, '\tcase BPF_FUNC_map_lookup_elem:',
               '\tcase BPF_FUNC_get_socket_cookie: return &bpf_get_socket_cookie_sock_proto;\n\tcase BPF_FUNC_map_lookup_elem:')
text = inside(text, 'cg_sockopt_is_valid_access', lambda body:
    replace(body, '\tswitch (off) {\n\tcase offsetof(struct bpf_sockopt, optval):',
            '\tswitch (off) {\n\tcase offsetof(struct bpf_sockopt, sk):\n'
            '\t\tif (size != 8) return false;\n\t\tinfo->reg_type = PTR_TO_SOCKET;\n\t\treturn true;\n'
            '\tcase offsetof(struct bpf_sockopt, optval):'))
text = replace(text, '\t\t/* PTR_TO_SOCKET and its verifier rules need a separate backport.\n'
                    '\t\t * Do not expose a kernel pointer as an untyped scalar.\n\t\t */\n', '')
changes[name] = replace(text, '\tCONVERT_FIELD(level);', '\tCONVERT_FIELD(sk);\n\tCONVERT_FIELD(level);')

name = 'kernel/bpf/verifier.c'
text = read(name)
text = replace(text, '\t[PTR_TO_PACKET_END]\t= "pkt_end",',
               '\t[PTR_TO_PACKET_END]\t= "pkt_end",\n\t[PTR_TO_SOCKET]\t\t= "sock",')
text = inside(text, 'is_spillable_regtype', lambda body:
               replace(body, '\tcase PTR_TO_CTX:', '\tcase PTR_TO_CTX:\n\tcase PTR_TO_SOCKET:'))
text = inside(text, 'regsafe', lambda body:
    replace(body, '\tswitch (rold->type) {',
            '\t/* A path checked as an untyped scalar must never prune a path\n'
            '\t * carrying a socket: its helper/leak restrictions differ.\n\t */\n'
            '\tif (rcur->type == PTR_TO_SOCKET && rold->type != PTR_TO_SOCKET)\n'
            '\t\treturn false;\n\tswitch (rold->type) {'))
text = inside(text, '__is_pointer_value', lambda body:
               replace(body, '\tif (allow_ptr_leaks)',
                       '\t/* A borrowed socket must not escape as an untyped address. */\n'
                       '\tif (reg->type == PTR_TO_SOCKET)\n\t\treturn true;\n\tif (allow_ptr_leaks)'))
text = replace(text, 'static int check_mem_access(',
               (package / 'kernel-patches/socket-verifier-access.c').read_text() + '\nstatic int check_mem_access(')
text = inside(text, 'check_mem_access', lambda body:
    replace(body, '\t/* alignment checks will add in reg->off themselves */',
            '\tif (reg->type == PTR_TO_SOCKET && !bpf_sock_reg_is_unmodified(reg))\n\t\treturn -EACCES;\n\n'
            '\t/* alignment checks will add in reg->off themselves */'))
text = inside(text, 'check_mem_access', lambda body:
    replace(body, '\t} else if (reg->type == PTR_TO_STACK) {',
            '\t} else if (reg->type == PTR_TO_SOCKET) {\n'
            '\t\terr = check_sock_access(env, insn_idx, regno, off, size, t);\n'
            '\t\tif (!err && t == BPF_READ && value_regno >= 0)\n'
            '\t\t\tmark_reg_unknown(state->regs, value_regno);\n'
            '\t} else if (reg->type == PTR_TO_STACK) {'))
text = inside(text, 'check_func_arg', lambda body:
    replace(body, '\t} else if (arg_type == ARG_PTR_TO_MEM ||',
            '\t} else if (arg_type == ARG_PTR_TO_SOCKET) {\n'
            '\t\texpected_type = PTR_TO_SOCKET;\n'
            '\t\tif (type != expected_type)\n\t\t\tgoto err_type;\n'
            '\t\tif (!bpf_sock_reg_is_unmodified(reg))\n\t\t\treturn -EACCES;\n'
            '\t} else if (arg_type == ARG_PTR_TO_MEM ||'))
text = inside(text, 'adjust_ptr_min_max_vals', lambda body:
    replace(body, '\tif (ptr_reg->type == PTR_TO_PACKET_END) {',
            '\tif (ptr_reg->type == PTR_TO_SOCKET) {\n'
            '\t\tverbose("socket pointer arithmetic is prohibited\\n");\n\t\treturn -EACCES;\n\t}\n'
            '\tif (ptr_reg->type == PTR_TO_PACKET_END) {'))
nonnull = '''
    if (BPF_SRC(insn->code) == BPF_K && insn->imm == 0 &&
        (opcode == BPF_JEQ || opcode == BPF_JNE) && dst_reg->type == PTR_TO_SOCKET) {
        /* This type is supplied only by a holding, non-NULL hook context. */
        if (opcode == BPF_JNE)
            *insn_idx += insn->off;
        return 0;
    }
'''
text = inside(text, 'check_cond_jmp_op', lambda body:
    replace(body, '\t/* detect if R == 0 where R was initialized to zero earlier */',
            nonnull + '\n\t/* detect if R == 0 where R was initialized to zero earlier */'))
text = replace(text, '(src_reg_type == PTR_TO_CTX ||\n\t\t\t\t    *prev_src_type == PTR_TO_CTX)',
               '(bpf_ptr_needs_conversion(src_reg_type) ||\n\t\t\t\t    bpf_ptr_needs_conversion(*prev_src_type))')
text = replace(text, '(dst_reg_type == PTR_TO_CTX ||\n\t\t\t\t    *prev_dst_type == PTR_TO_CTX)',
               '(bpf_ptr_needs_conversion(dst_reg_type) ||\n\t\t\t\t    bpf_ptr_needs_conversion(*prev_dst_type))')
text = inside(text, 'convert_ctx_accesses', lambda body:
    replace(body, '\tu32 target_size;', '\tu32 target_size, original_offset;\n\tenum bpf_reg_type ptr_type;\n'
            '\tu32 (*convert_access)(enum bpf_access_type, const struct bpf_insn *,\n'
            '\t\tstruct bpf_insn *, struct bpf_prog *, u32 *);'))
text = inside(text, 'convert_ctx_accesses', lambda body:
               replace(body, '\tif (!ops->convert_ctx_access)\n\t\treturn 0;\n', ''))
selection = '''
        ptr_type = env->insn_aux_data[i + delta].ptr_type;
        if (ptr_type == PTR_TO_SOCKET) {
            convert_access = bpf_sock_convert_ctx_access;
        } else if (ptr_type == PTR_TO_CTX && ops->convert_ctx_access) {
            convert_access = ops->convert_ctx_access;
        } else {
            continue;
        }
        original_offset = insn->off;
'''
text = inside(text, 'convert_ctx_accesses', lambda body:
    replace(body, '\t\tif (env->insn_aux_data[i + delta].ptr_type != PTR_TO_CTX)\n\t\t\tcontinue;', selection))
text = inside(text, 'convert_ctx_accesses', lambda body:
               replace(body, 'cnt = ops->convert_ctx_access(', 'cnt = convert_access('))
narrow = '''
        if (is_narrower_load && ptr_type == PTR_TO_SOCKET) {
            u32 byte_offset = original_offset & 3;
#ifdef __LITTLE_ENDIAN
            u32 shift = byte_offset * 8;
#else
            u32 shift = (4 - size - byte_offset) * 8;
#endif
            /* Translate the logical 32-bit field, including zero padding of
             * 8/16-bit kernel members, before selecting its requested bytes.
             */
            if (shift)
                insn_buf[cnt++] = BPF_ALU32_IMM(BPF_RSH, insn->dst_reg, shift);
            insn_buf[cnt++] = BPF_ALU32_IMM(BPF_AND, insn->dst_reg, (1U << (size * 8)) - 1);
        } else if (is_narrower_load && size < target_size) {
'''
text = inside(text, 'convert_ctx_accesses', lambda body:
    replace(body, '\t\tif (is_narrower_load && size < target_size) {', narrow))
changes[name] = text

# Prevalidate all replacements before changing the real kernel.
backup = package / 'validation/bpf-socket-pointer-before'
patch = []
for name, after in changes.items():
    target = backup / name
    assert not target.exists()
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(before[name])
    patch.extend(difflib.unified_diff(before[name].splitlines(True), after.splitlines(True),
                                    fromfile='a/' + name, tofile='b/' + name))
path = package / 'kernel-patches/0003-r24u-borrowed-socket.patch'
path.write_text(''.join(patch))
for name, after in changes.items():
    (kernel / name).write_text(after)
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
record = {'kernel_commit': commit, 'scope': 'Borrowed socket typing, read-only metadata and cookie helper',
          'predecessor_patch_sha256': sha(package / 'kernel-patches/0002-r24u-map-batch.patch'),
          'patch_sha256': sha(path), 'before_sha256': {n: sha(backup / n) for n in changes},
          'changed_files': {n: sha(kernel / n) for n in changes},
          'unsupported': ['Nullable/acquired sockets and reference-tracking helpers',
                          'Socket storage and its helper implementations', 'RX queue mapping is unavailable (-1)'],
          'affected_units_compile_passed': False, 'full_kernel_link_passed': False,
          'device_tested': False, 'android17_network_validated': False, 'installable_package': False}
record_path.write_text(json.dumps(record, indent=2) + '\n')
print('Borrowed socket source port installed; native/security/translation validation pending.')
