#!/usr/bin/env python3
"""Exercise installed socket guards and instruction conversion with host plumbing.

These are sanitizer tests of actual C functions, not loaded BPF/device tests.
The mock sock layout deliberately differs from the logical UAPI layout.
"""
from pathlib import Path
import hashlib
import json
import re
import resource
import subprocess
import tempfile

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
names = ['net/core/filter.c', 'kernel/bpf/verifier.c', 'include/uapi/linux/bpf.h']
sources = {name: (kernel / name).read_text() for name in names}


def function(text, name):
    match = re.search(r'^[ \t]*(?:static[ \t]+)?(?:int|bool|u32)[ \t]+' +
                      name + r'\([^;{}]*?\)\s*\{', text, re.M)
    assert match, name
    end = text.index('{', match.start()) + 1
    depth = 1
    while depth:
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        end += 1
    return text[match.start():end]


sock = re.search(r'struct bpf_sock \{.*?\n\};', sources[names[2]], re.S).group()
reference = (package / 'validation/bpf-reference/linux-v5.10/include/uapi/linux/bpf.h').read_text()
reference_sock = re.search(r'struct bpf_sock \{.*?\n\};', reference, re.S).group()
fields = lambda value: re.findall(r'(__[us]\d+)\s+(\w+)(\[\d+\])?\s*;', value)
assert fields(sock) == fields(reference_sock), 'Socket UAPI differs from the pinned upstream ABI'

prefix = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <limits.h>
typedef uint8_t u8;
typedef uint32_t u32;
typedef uint32_t __u32;
typedef int32_t __s32;
#undef __LITTLE_ENDIAN
#undef __BIG_ENDIAN
#if TEST_BIG_ENDIAN
#define __BIG_ENDIAN 4321
#define SK_FL_PROTO_SHIFT 16
#define SK_FL_PROTO_MASK 0x00ff0000
#define SK_FL_TYPE_SHIFT 0
#define SK_FL_TYPE_MASK 0x0000ffff
#else
#define __LITTLE_ENDIAN 1234
#define SK_FL_PROTO_SHIFT 8
#define SK_FL_PROTO_MASK 0x0000ff00
#define SK_FL_TYPE_SHIFT 16
#define SK_FL_TYPE_MASK 0xffff0000
#endif
#define CONFIG_IPV6 TEST_IPV6
#define IS_ENABLED(x) (x)
#define ARRAY_SIZE(x) (sizeof(x)/sizeof(*(x)))
#define verbose(...) ((void)0)
#define FIELD_SIZEOF(t,m) sizeof(((t *)0)->m)
#define BUILD_BUG_ON(x) _Static_assert(!(x), "field width")
#define offsetofend(t,m) (offsetof(t,m) + FIELD_SIZEOF(t,m))
#define bpf_ctx_range_till(t,a,b) offsetof(t,a) ... offsetofend(t,b)-1
#define bpf_target_off(t,m,s,p) ({ BUILD_BUG_ON(FIELD_SIZEOF(t,m)!=(s)); *(p)=(s); offsetof(t,m); })
#define BPF_LD 0x00
#define BPF_LDX 0x01
#define BPF_ST 0x02
#define BPF_STX 0x03
#define BPF_ALU 0x04
#define BPF_JMP 0x05
#define BPF_ALU64 0x07
#define BPF_MEM 0x60
#define BPF_X 0x08
#define BPF_W 0x00
#define BPF_H 0x08
#define BPF_B 0x10
#define BPF_DW 0x18
#define BPF_AND 0x50
#define BPF_RSH 0x70
#define BPF_MOV 0xb0
#define BPF_SIZE(c) ((c)&0x18)
#define BPF_CLASS(c) ((c)&0x07)
#define BPF_REG_FP 10
struct bpf_insn { u8 code; u8 dst_reg; u8 src_reg; int16_t off; int32_t imm; };
#define MAKE_INSN(c,d,s,o,i) ((struct bpf_insn){(c),(d),(s),(o),(i)})
#define BPF_LDX_MEM(z,d,s,o) MAKE_INSN(BPF_LDX|BPF_MEM|(z),d,s,o,0)
#define BPF_STX_MEM(z,d,s,o) MAKE_INSN(BPF_STX|BPF_MEM|(z),d,s,o,0)
#define BPF_ST_MEM(z,d,o,i) MAKE_INSN(BPF_ST|BPF_MEM|(z),d,0,o,i)
#define BPF_ALU32_IMM(op,d,i) MAKE_INSN(BPF_ALU|(op),d,0,0,i)
#define BPF_ALU64_IMM(op,d,i) MAKE_INSN(BPF_ALU64|(op),d,0,0,i)
#define BPF_MOV32_IMM(d,i) BPF_ALU32_IMM(BPF_MOV,d,i)
#define BPF_LDST_BYTES(x) (BPF_SIZE((x)->code)==BPF_B?1:BPF_SIZE((x)->code)==BPF_H?2:BPF_SIZE((x)->code)==BPF_W?4:8)
#define BPF_FIELD_SIZEOF(t,m) (FIELD_SIZEOF(t,m)==1?BPF_B:FIELD_SIZEOF(t,m)==2?BPF_H:BPF_W)
enum bpf_access_type { BPF_READ, BPF_WRITE };
enum bpf_reg_type { NOT_INIT, SCALAR_VALUE, PTR_TO_CTX, PTR_TO_STACK, PTR_TO_SOCKET, PTR_TO_MAP_VALUE,
    PTR_TO_MAP_VALUE_OR_NULL, PTR_TO_PACKET, PTR_TO_PACKET_END, CONST_PTR_TO_MAP };
struct bpf_insn_access_aux { enum bpf_reg_type reg_type; int ctx_field_size; };
struct tnum { uint64_t value, mask; };
static bool tnum_is_const(struct tnum n) { return !n.mask; }
struct bpf_reg_state { enum bpf_reg_type type; int off; struct tnum var_off;
    int id, range; int64_t smin_value, smax_value; uint64_t umin_value, umax_value; };
struct idpair { int old, current; };
#define U64_MAX UINT64_MAX
#define S64_MIN INT64_MIN
#define S64_MAX INT64_MAX
#define WARN_ON_ONCE(x) assert(!(x))
static bool tnum_is_unknown(struct tnum n) { return n.mask==UINT64_MAX && !n.value; }
static bool tnum_in(struct tnum a, struct tnum b) { return !(b.mask & ~a.mask) && !((a.value^b.value)&~a.mask); }
static bool range_within(struct bpf_reg_state *a, struct bpf_reg_state *b) {
    return a->umin_value<=b->umin_value && a->umax_value>=b->umax_value &&
        a->smin_value<=b->smin_value && a->smax_value>=b->smax_value;
}
static bool check_ids(int a,int b,struct idpair *m) { return a==b; }
struct sock_common {
    uint32_t skc_daddr, skc_rcv_saddr;
    uint16_t skc_dport, skc_num, skc_family;
    uint8_t skc_state;
    struct { uint32_t s6_addr32[4]; } skc_v6_daddr, skc_v6_rcv_saddr;
};
struct sock { struct sock_common common; uint8_t padding[37];
    uint32_t flags, sk_bound_dev_if, sk_mark, sk_priority; };
#define sk_family common.skc_family
#define __sk_flags_offset flags
struct bpf_prog { int len; struct bpf_insn insnsi[64]; };
struct bpf_insn_aux_data { enum bpf_reg_type ptr_type; int ctx_field_size, sanitize_stack_off; };
struct bpf_verifier_ops {
    int (*gen_prologue)(struct bpf_insn *,bool,struct bpf_prog *);
    u32 (*convert_ctx_access)(enum bpf_access_type,const struct bpf_insn *,struct bpf_insn *,struct bpf_prog *,u32 *);
};
struct bpf_verifier_env { struct {struct bpf_reg_state regs[11];} cur_state;
    struct bpf_insn_aux_data insn_aux_data[64]; struct bpf_prog *prog;
    const struct bpf_verifier_ops *ops; bool seen_direct_write; };
static struct bpf_prog *bpf_patch_insn_data(struct bpf_verifier_env *env, int at,
                                          struct bpf_insn *patch, int count) {
    struct bpf_prog *old=env->prog, *out=calloc(1,sizeof(*out)); assert(out);
    assert(at>=0 && at<old->len && count>0 && old->len+count-1<64);
    out->len=old->len+count-1;
    memcpy(out->insnsi,old->insnsi,at*sizeof(*patch));
    memcpy(out->insnsi+at,patch,count*sizeof(*patch));
    memcpy(out->insnsi+at+count,old->insnsi+at+1,(old->len-at-1)*sizeof(*patch));
    memmove(env->insn_aux_data+at+count,env->insn_aux_data+at+1,
            (old->len-at-1)*sizeof(*env->insn_aux_data));
    free(old); return out;
}
'''
prefix += '\n' + sock + '\n'
for name in ['bpf_sock_is_valid_access', 'bpf_sock_convert_ctx_access']:
    prefix += function(sources[names[0]], name) + '\n'
for name in ['bpf_sock_reg_is_unmodified', 'check_sock_access', '__is_pointer_value', 'regsafe',
             'bpf_ptr_needs_conversion', 'convert_ctx_accesses']:
    prefix += function(sources[names[1]], name) + '\n'

main = r'''
static int cases;
static void put(unsigned char *mem, int off, int size, uint32_t value) {
    for(int b=0;b<size;b++) mem[off+b]=(value >> ((TEST_BIG_ENDIAN?size-1-b:b)*8))&255;
}
static uint64_t execute(struct bpf_prog *prog, const unsigned char *mem) {
    uint64_t out=UINT64_MAX;
    for(int i=0;i<prog->len;i++) {
        struct bpf_insn *in=&prog->insnsi[i];
        if(BPF_CLASS(in->code)==BPF_LDX) {
            int size=BPF_LDST_BYTES(in); assert(in->off>=0 && in->off+size<=sizeof(struct sock));
            out=0; for(int b=0;b<size;b++)
                out|=(uint64_t)mem[in->off+b]<<((TEST_BIG_ENDIAN?size-1-b:b)*8);
        } else {
            assert(BPF_CLASS(in->code)==BPF_ALU);
            switch(in->code & 0xf0) {
            case BPF_AND: out=(uint32_t)out & (uint32_t)in->imm; break;
            case BPF_RSH: assert(in->imm<32); out=(uint32_t)out >> in->imm; break;
            case BPF_MOV: out=(uint32_t)in->imm; break;
            default: assert(false);
            }
        }
    }
    return out;
}
static void guard_tests(void) {
    const int sizes[]={INT_MIN,-4,-1,0,1,2,3,4,8,16,INT_MAX};
    struct bpf_verifier_env env={0};
    env.cur_state.regs[1].type=PTR_TO_SOCKET;
    for(int off=-8;off<=88;off++) for(size_t i=0;i<ARRAY_SIZE(sizes);i++) for(int write=0;write<2;write++) {
        int size=sizes[i]; struct bpf_insn_access_aux info={0};
        bool expected=!write && (size==1||size==2||size==4) && off>=0 && off<=80-size && !(off%size);
        if(expected && ((off&~3)==0 || (off&~3)==16 || (off&~3)==20) && size!=4) expected=false;
        assert(bpf_sock_is_valid_access(off,size,write?BPF_WRITE:BPF_READ,&info)==expected);
        assert((check_sock_access(&env,0,1,off,size,write?BPF_WRITE:BPF_READ)==0)==expected);
        if(expected) assert(info.ctx_field_size==4 && env.insn_aux_data[0].ctx_field_size==4);
        cases++;
    }
    assert(bpf_sock_reg_is_unmodified(&env.cur_state.regs[1]));
    assert(__is_pointer_value(false,&env.cur_state.regs[1]));
    assert(__is_pointer_value(true,&env.cur_state.regs[1])); cases+=3;
    struct bpf_reg_state base=env.cur_state.regs[1];
    for(int field=0;field<7;field++) for(int n=-1;n<=1;n+=2) {
        struct bpf_reg_state *r=&env.cur_state.regs[1]; *r=base;
        switch(field) {
        case 0:r->off=n;break; case 1:r->var_off.value=(uint64_t)n;break;
        case 2:r->var_off.mask=(uint64_t)n;break; case 3:r->smin_value=n;break;
        case 4:r->smax_value=n;break; case 5:r->umin_value=(uint64_t)n;break;
        case 6:r->umax_value=(uint64_t)n;break;
        }
        assert(!bpf_sock_reg_is_unmodified(r)); assert(check_sock_access(&env,0,1,4,4,BPF_READ)==-EACCES); cases++;
    }
    for(int type=NOT_INIT;type<=PTR_TO_MAP_VALUE;type++) {
        struct bpf_reg_state r=base;r.type=type;
        assert(bpf_sock_reg_is_unmodified(&r)==(type==PTR_TO_SOCKET));
        assert(bpf_ptr_needs_conversion(type)==(type==PTR_TO_CTX||type==PTR_TO_SOCKET)); cases++;
    }
}
static void translation_tests(void) {
    const struct bpf_verifier_ops ops={.convert_ctx_access=bpf_sock_convert_ctx_access};
    const struct bpf_verifier_ops no_ctx_ops={0};
    const uint32_t values[]={0,1,0x000000ff,0x00000100,0x0000ffff,0x00ff1234,0x80000000,UINT32_MAX};
    const int real_offsets[]={offsetof(struct sock,sk_bound_dev_if),offsetof(struct sock,sk_family),
        offsetof(struct sock,flags),offsetof(struct sock,flags),offsetof(struct sock,sk_mark),offsetof(struct sock,sk_priority),
        offsetof(struct sock_common,skc_rcv_saddr),offsetof(struct sock_common,skc_v6_rcv_saddr.s6_addr32[0]),
        offsetof(struct sock_common,skc_v6_rcv_saddr.s6_addr32[1]),offsetof(struct sock_common,skc_v6_rcv_saddr.s6_addr32[2]),
        offsetof(struct sock_common,skc_v6_rcv_saddr.s6_addr32[3]),offsetof(struct sock_common,skc_num),
        offsetof(struct sock_common,skc_dport),offsetof(struct sock_common,skc_daddr),
        offsetof(struct sock_common,skc_v6_daddr.s6_addr32[0]),offsetof(struct sock_common,skc_v6_daddr.s6_addr32[1]),
        offsetof(struct sock_common,skc_v6_daddr.s6_addr32[2]),offsetof(struct sock_common,skc_v6_daddr.s6_addr32[3]),
        offsetof(struct sock_common,skc_state),-1};
    for(int f=0;f<20;f++) for(size_t val=0;val<ARRAY_SIZE(values);val++) {
        unsigned char mem[sizeof(struct sock)];memset(mem,0xa5,sizeof(mem));
        int width=4;uint32_t v=values[val], stored=v;
        if(f==1||f==11||f==12) {width=2;v&=0xffff;stored=v;}
        if(f==18) {width=1;v&=0xff;stored=v;}
        if(f==2) {v&=0xffff;stored=(v<<SK_FL_TYPE_SHIFT)|SK_FL_PROTO_MASK;}
        if(f==3) {v&=0xff;stored=(v<<SK_FL_PROTO_SHIFT)|SK_FL_TYPE_MASK;}
        if(f==19) v=UINT32_MAX;
        if(!TEST_IPV6 && ((f>=7&&f<=10)||(f>=14&&f<=17))) v=0;
        if(real_offsets[f]>=0) put(mem,real_offsets[f],width,stored);
        for(int size=1;size<=4;size*=2) for(int byte=0;byte<4;byte+=size) {
            struct bpf_insn_access_aux info={0};int off=f*4+byte;
            if(!bpf_sock_is_valid_access(off,size,BPF_READ,&info)) continue;
            struct bpf_verifier_env env={0};env.prog=calloc(1,sizeof(*env.prog));assert(env.prog);
            env.prog->len=1;env.prog->insnsi[0]=BPF_LDX_MEM(size==1?BPF_B:size==2?BPF_H:BPF_W,0,1,off);
            env.insn_aux_data[0].ptr_type=PTR_TO_SOCKET;env.insn_aux_data[0].ctx_field_size=4;
            env.ops=(val&1)?&ops:&no_ctx_ops;
            assert(convert_ctx_accesses(&env)==0);
            uint64_t actual=execute(env.prog,mem);
            int shift=(TEST_BIG_ENDIAN?4-size-byte:byte)*8;
            uint64_t mask=size==4?UINT32_MAX:(1u<<(size*8))-1;
            assert(actual==((v>>shift)&mask));assert(actual<=UINT32_MAX);free(env.prog);cases++;
        }
    }
    // A mixed program exercises aux relocation when its first access expands.
    struct bpf_verifier_env env={0};env.ops=&no_ctx_ops;env.prog=calloc(1,sizeof(*env.prog));assert(env.prog);
    env.prog->len=3;
    for(int i=0;i<3;i++) {env.prog->insnsi[i]=BPF_LDX_MEM(BPF_B,0,1,8+i);env.insn_aux_data[i].ptr_type=PTR_TO_SOCKET;env.insn_aux_data[i].ctx_field_size=4;}
    assert(convert_ctx_accesses(&env)==0 && env.prog->len>=12);free(env.prog);cases++;
    // Raw map access must remain untouched when the context converter is absent.
    memset(&env,0,sizeof(env));env.ops=&no_ctx_ops;env.prog=calloc(1,sizeof(*env.prog));assert(env.prog);
    env.prog->len=1;env.prog->insnsi[0]=BPF_LDX_MEM(BPF_W,0,1,12);env.insn_aux_data[0].ptr_type=PTR_TO_MAP_VALUE;
    assert(convert_ctx_accesses(&env)==0 && env.prog->len==1 && env.prog->insnsi[0].off==12);free(env.prog);cases++;
}
static void pruning_tests(void) {
    struct bpf_reg_state scalar={.type=SCALAR_VALUE,.smin_value=INT64_MIN,.smax_value=INT64_MAX,
        .umin_value=0,.umax_value=UINT64_MAX,.var_off={.value=0,.mask=UINT64_MAX}};
    struct bpf_reg_state socket={.type=PTR_TO_SOCKET};struct idpair idmap={0};
    for(int variable=0;variable<2;variable++) {
        // This used to accept the socket as satisfying an unknown scalar path.
        assert(!regsafe(&scalar,&socket,variable,&idmap));cases++;
        assert(!regsafe(&socket,&scalar,variable,&idmap));cases++;
        assert(regsafe(&socket,&socket,variable,&idmap));cases++;
        struct bpf_reg_state unused={.type=NOT_INIT};
        assert(regsafe(&unused,&socket,variable,&idmap));cases++;
        assert(!regsafe(&socket,&unused,variable,&idmap));cases++;
        struct bpf_reg_state bounded={.type=SCALAR_VALUE,.smin_value=0,.smax_value=1,.umin_value=0,.umax_value=1,
            .var_off={.value=0,.mask=1}};
        assert(regsafe(&scalar,&bounded,variable,&idmap));cases++;
    }
}
int main(void) {
    _Static_assert(sizeof(struct bpf_sock)==80,"socket ABI");
    _Static_assert(offsetof(struct bpf_sock,dst_port)==48,"destination ABI");
    _Static_assert(offsetof(struct bpf_sock,rx_queue_mapping)==76,"RX ABI");
    guard_tests();translation_tests();pruning_tests();printf("{\"cases\":%d,\"passed\":true}\n",cases);return 0;
}
'''
verifier = sources[names[1]]
# The real verifier call sites must keep the helpers in their responsible paths.
assert 'if (reg->type == PTR_TO_SOCKET && !bpf_sock_reg_is_unmodified(reg))' in function(verifier, 'check_mem_access')
assert 'check_sock_access(env, insn_idx, regno, off, size, t)' in function(verifier, 'check_mem_access')
arg = function(verifier, 'check_func_arg')
assert 'arg_type == ARG_PTR_TO_SOCKET' in arg and '!bpf_sock_reg_is_unmodified(reg)' in arg
assert 'ptr_reg->type == PTR_TO_SOCKET' in function(verifier, 'adjust_ptr_min_max_vals')
assert 'bpf_ptr_needs_conversion(src_reg_type)' in verifier
assert 'bpf_ptr_needs_conversion(dst_reg_type)' in verifier
results = {}
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
with tempfile.TemporaryDirectory(prefix='borealis-bpf-socket-pointer-') as temp:
    directory = Path(temp)
    harness = directory / 'socket-pointer.c'
    harness.write_text(prefix + main)
    for big in (0, 1):
        for ipv6 in (0, 1):
            key = f'{"big" if big else "little"}_endian_ipv6_{ipv6}'
            binary = directory / key
            subprocess.run(['gcc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', '-no-pie', f'-DTEST_BIG_ENDIAN={big}',
                            f'-DTEST_IPV6={ipv6}', str(harness), '-o', str(binary)], check=True)
            results[key] = json.loads(subprocess.check_output([str(binary)], text=True))
    # Prove that the pruning case detects the old behavior, rather than only
    # mirroring the newly inserted check. Expected assert failure stays local.
    old_guard = '\tif (rcur->type == PTR_TO_SOCKET && rold->type != PTR_TO_SOCKET)\n\t\treturn false;\n'
    assert prefix.count(old_guard) == 1
    regression = directory / 'pruning-before.c'
    regression.write_text(prefix.replace(old_guard, '', 1) + main)
    regression_binary = directory / 'pruning-before'
    subprocess.run(['gcc', '-std=gnu11', '-O1', '-DTEST_BIG_ENDIAN=0', '-DTEST_IPV6=1',
                    str(regression), '-o', str(regression_binary)], check=True)
    failure = subprocess.run([str(regression_binary)], capture_output=True, text=True)
    assert failure.returncode != 0 and '!regsafe(&scalar,&socket' in failure.stderr
    abi = directory / 'abi.c'
    abi.write_text('typedef unsigned int __u32; typedef int __s32;\n' + sock + '\n'
                   '_Static_assert(sizeof(struct bpf_sock)==80,"size");\n'
                   '_Static_assert(__builtin_offsetof(struct bpf_sock,dst_port)==48,"dst");\n'
                   '_Static_assert(__builtin_offsetof(struct bpf_sock,rx_queue_mapping)==76,"RX");\n')
    for target in ('aarch64-linux-gnu', 'armv7-linux-gnueabi'):
        subprocess.run(['/home/android/nebula-kernel-v1.0/toolchain/bin/clang', '-target', target,
                        '-std=gnu11', '-nostdinc', '-fsyntax-only', str(abi)], check=True)
report = {'scope': 'Installed C socket guards/converter with simulated sock, allocator and BPF execution; no loaded programs',
          'variants': results, 'cases': sum(r['cases'] for r in results.values()),
          'asan_ubsan': 'passed', 'uapi_layout_arm32_arm64': 'passed',
          'upstream_uapi_fields_match': True,
          'pre_fix_pruning_regression_reproduced': True,
          'source_sha256': {n: hashlib.sha256(s.encode()).hexdigest() for n, s in sources.items()},
          'device_tested': False, 'android17_network_validated': False,
          'reference_tracking_or_storage_implemented': False}
(package / 'validation/bpf-socket-pointer-tests.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
