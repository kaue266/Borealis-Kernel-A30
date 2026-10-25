#!/usr/bin/env python3
"""Exercise actual backport functions under sanitizers, plus ARM UAPI layouts."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import tempfile

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
source = (kernel / 'kernel/bpf/sockopt.c').read_text()
uapi = (kernel / 'include/uapi/linux/bpf.h').read_text()
filter_header = (kernel / 'include/linux/filter.h').read_text()


def function(text, name):
    match = re.search(r'\b' + name + r'\([^;]*?\)\s*\{', text)
    assert match, name
    start = text.rfind('\n', 0, match.start()) + 1
    # Include split return types on their preceding line.
    if name in ('cg_sockopt_is_valid_access',):
        start = text.rfind('\n', 0, start - 1) + 1 if text[start:match.start()].strip() == '' else start
    end = text.index('{', match.start()) + 1
    depth = 1
    while depth:
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        end += 1
    return text[start:end]


enums = '\n'.join(re.search(r'enum ' + name + r'\s*\{.*?\};', uapi, re.S).group()
                  for name in ('bpf_prog_type', 'bpf_attach_type'))
ctx = re.search(r'struct bpf_sockopt \{.*?\n\};', uapi, re.S).group()
internal_ctx = re.search(r'struct bpf_sockopt_kern \{.*?\n\};', filter_header, re.S).group()
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
typedef uint64_t __u64;
typedef int32_t __s32;
typedef int32_t s32;
typedef uint8_t u8;
#define __user
#define EXPORT_SYMBOL(x)
#define __bpf_md_ptr(type, name) union { type name; __u64 :64; } __attribute__((aligned(8)))
#define PAGE_SIZE 4096
#define GFP_USER 0
#define min(x,y) ((x)<(y)?(x):(y))
#define min_t(t,x,y) min((t)(x),(t)(y))
#define max_t(t,x,y) ((t)(x)>(t)(y)?(t)(x):(t)(y))
#define READ_ONCE(x) (x)
#define rcu_read_lock() ((void)0)
#define rcu_read_unlock() ((void)0)
#define rcu_dereference(x) (x)
enum bpf_access_type { BPF_READ, BPF_WRITE };
enum bpf_reg_type { SCALAR_VALUE, PTR_TO_PACKET, PTR_TO_PACKET_END, PTR_TO_SOCKET };
struct bpf_insn_access_aux { enum bpf_reg_type reg_type; int ctx_field_size; };
'''
prefix += enums + '\n' + r'''
struct bpf_prog { enum bpf_attach_type expected_attach_type; enum bpf_prog_type type; };
struct bpf_prog_array { struct bpf_prog *progs[4]; };
struct cgroup { struct { struct bpf_prog_array *effective[__MAX_BPF_ATTACH_TYPE]; } bpf; };
struct socket_group { struct cgroup *ptr; };
struct sock { struct socket_group sk_cgrp_data; };
static struct { struct bpf_prog prog; } dummy_bpf_prog;
static struct bpf_prog live_prog;
static struct bpf_prog_array empty, attached;
static struct cgroup group;
static struct sock socket_fixture;
static bool cgroup_bpf_enabled;
static struct cgroup *sock_cgroup_ptr(struct socket_group *data) { return data->ptr; }
#define lock_sock(x) ((void)0)
#define release_sock(x) ((void)0)
static void *allocated;
static size_t allocated_bytes;
static int live_allocations, allocations, fail_alloc, fail_read, fail_write, fail_get, fail_put;
static void *kzalloc(size_t length, int flags) {
    if (fail_alloc) return NULL;
    assert(!allocated);
    allocated=calloc(1,length); assert(allocated);
    allocated_bytes=length; live_allocations++; allocations++;
    return allocated;
}
static void kfree(void *pointer) {
    if (!pointer) return;
    assert(pointer == allocated);
    free(pointer); allocated=NULL; allocated_bytes=0; live_allocations--;
}
static int copy_from_user(void *destination, const void *input, size_t length) {
    if (fail_read || !input) return 1;
    assert(destination == allocated && length <= allocated_bytes);
    memcpy(destination,input,length); return 0;
}
static int copy_to_user(void *destination, const void *input, size_t length) {
    if (fail_write || !destination) return 1;
    assert(input == allocated && length <= allocated_bytes);
    memcpy(destination,input,length); return 0;
}
#define get_user(value,pointer) ({ int result=fail_get||!(pointer); if (!result) value=*(pointer); result; })
#define put_user(value,pointer) ({ int result=fail_put||!(pointer); if (!result) *(pointer)=value; result; })
'''
prefix += ctx + '\n' + internal_ctx + '\n'
prefix += r'''
enum behavior { KEEP, DENY, BYPASS, ZERO_LENGTH, NEGATIVE_LENGTH, TOO_LONG, ALTER, BAD_RETVAL };
static enum behavior behavior;
static int run_program(void *context) {
    struct bpf_sockopt_kern *ctx=context;
    if (behavior==DENY) return 0;
    if (behavior==BYPASS) ctx->optlen=-1;
    if (behavior==ZERO_LENGTH) ctx->optlen=0;
    if (behavior==NEGATIVE_LENGTH) ctx->optlen=-2;
    if (behavior==TOO_LONG) ctx->optlen=(ctx->optval_end-ctx->optval)+1;
    if (behavior==BAD_RETVAL) ctx->retval=-EACCES;
    if (behavior==ALTER) {
        ctx->optlen=4; ctx->level=6; ctx->optname=9;
        memset(ctx->optval,0x5a,4);
    }
    return 1;
}
#define BPF_PROG_RUN_ARRAY_CHECK(array,context,function) run_program(context)
'''
prefix += function((kernel / 'kernel/bpf/core.c').read_text(), 'bpf_prog_array_is_empty') + '\n'
for name in ('sockopt_prog_array_empty', 'sockopt_alloc_buf',
             '__cgroup_bpf_run_filter_setsockopt', '__cgroup_bpf_run_filter_getsockopt',
             'cg_sockopt_is_valid_access'):
    prefix += function(source, name) + '\n'
syscall = (kernel / 'kernel/bpf/syscall.c').read_text()
prefix += 'static int\n' + function(syscall, 'bpf_prog_load_check_attach_type') + '\n'
prefix += function(syscall, 'bpf_prog_attach_check_attach_type') + '\n'

main = r'''
static void reset(void) {
    assert(live_allocations==0);
    memset(&group,0,sizeof(group)); memset(&empty,0,sizeof(empty));
    memset(&attached,0,sizeof(attached));
    attached.progs[0]=&live_prog;
    group.bpf.effective[BPF_CGROUP_SETSOCKOPT]=&attached;
    group.bpf.effective[BPF_CGROUP_GETSOCKOPT]=&attached;
    socket_fixture.sk_cgrp_data.ptr=&group;
    cgroup_bpf_enabled=true; allocations=0;
    fail_alloc=fail_read=fail_write=fail_get=fail_put=0;
    behavior=KEEP;
}
static int setter(int length, void **output) {
    char buffer[8192]={0}; int level=1,name=2;
    return __cgroup_bpf_run_filter_setsockopt(&socket_fixture,&level,&name,buffer,&length,(char **)output);
}
static int getter(int capacity, int length, int retval) {
    char buffer[8192]={0};
    return __cgroup_bpf_run_filter_getsockopt(&socket_fixture,1,2,buffer,&length,capacity,retval);
}
int main(void) {
    int cases=0;
    void *output=NULL;
    const int sizes[]={INT_MIN,-8,-1,0,1,2,3,4,8,16,INT_MAX};
    struct bpf_prog prog={0};
    _Static_assert(sizeof(struct bpf_sockopt)==40,"BPF context ABI");
    _Static_assert(offsetof(struct bpf_sockopt,retval)==36,"BPF retval ABI");

    for (int hook=21;hook<=22;hook++) for(int off=-8;off<=48;off++)
        for(size_t s=0;s<sizeof(sizes)/sizeof(*sizes);s++) for(int write=0;write<2;write++) {
            bool expected=false;
            int size=sizes[s];
            struct bpf_insn_access_aux info={0};
            prog.expected_attach_type=hook;
            if (!write && size==8 && (off==0 || off==8 || off==16)) expected=true;
            if (!write && size==4 && (off==24 || off==28 || off==32 || (off==36 && hook==21))) expected=true;
            if (write && size==4 && (off==32 || (hook==22 && (off==24 || off==28)) || (hook==21 && off==36))) expected=true;
            bool actual=cg_sockopt_is_valid_access(off,size,write?BPF_WRITE:BPF_READ,&prog,&info);
            assert(actual==expected);
            if (expected && !write && off==0) assert(info.reg_type==PTR_TO_SOCKET);
            if (expected && !write && off==8) assert(info.reg_type==PTR_TO_PACKET);
            if (expected && !write && off==16) assert(info.reg_type==PTR_TO_PACKET_END);
            cases++;
        }
    assert(bpf_prog_load_check_attach_type(BPF_PROG_TYPE_CGROUP_SOCKOPT,BPF_CGROUP_GETSOCKOPT)==0);
    assert(bpf_prog_load_check_attach_type(BPF_PROG_TYPE_CGROUP_SOCKOPT,BPF_CGROUP_SETSOCKOPT)==0);
    assert(bpf_prog_load_check_attach_type(BPF_PROG_TYPE_CGROUP_SOCKOPT,BPF_CGROUP_INET_SOCK_CREATE)==-EINVAL);
    prog.type=BPF_PROG_TYPE_CGROUP_SOCKOPT; prog.expected_attach_type=BPF_CGROUP_GETSOCKOPT;
    assert(bpf_prog_attach_check_attach_type(&prog,BPF_CGROUP_SETSOCKOPT)==-EINVAL);
    assert(bpf_prog_attach_check_attach_type(&prog,BPF_CGROUP_GETSOCKOPT)==0); cases+=5;

    reset(); assert(bpf_prog_array_is_empty(NULL)); assert(bpf_prog_array_is_empty(&empty));
    empty.progs[0]=&dummy_bpf_prog.prog; assert(bpf_prog_array_is_empty(&empty));
    empty.progs[1]=&live_prog; assert(!bpf_prog_array_is_empty(&empty)); cases+=4;

    reset(); cgroup_bpf_enabled=false;
    assert(setter(4,&output)==0 && !output && allocations==0);
    assert(getter(4,4,-EINVAL)==-EINVAL && allocations==0); cases+=2;
    reset(); group.bpf.effective[BPF_CGROUP_GETSOCKOPT]=NULL; group.bpf.effective[BPF_CGROUP_SETSOCKOPT]=&empty;
    assert(setter(4,&output)==0 && allocations==0);
    assert(getter(4,4,-EINVAL)==-EINVAL && allocations==0); cases+=2;

    reset(); fail_alloc=1; assert(setter(4,&output)==-ENOMEM); assert(getter(4,4,0)==-ENOMEM); cases+=2;
    reset(); fail_read=1; assert(setter(4,&output)==-EFAULT); assert(getter(4,4,0)==-EFAULT); cases+=2;
    reset(); behavior=DENY; assert(setter(4,&output)==-EPERM); assert(getter(4,4,0)==-EPERM); cases+=2;
    reset(); behavior=BYPASS; assert(setter(4,&output)==1 && !output); assert(getter(4,4,0)==-EFAULT); cases+=2;
    reset(); behavior=NEGATIVE_LENGTH; assert(setter(4,&output)==-EFAULT); assert(getter(4,4,0)==-EFAULT); cases+=2;
    reset(); behavior=TOO_LONG; assert(setter(4,&output)==-EFAULT); assert(getter(4,4,0)==-EFAULT); cases+=2;
    reset(); assert(setter(-1,&output)==-EINVAL); assert(getter(-1,4,0)==-EINVAL); assert(getter(4,-1,0)==-EFAULT); cases+=3;
    reset(); fail_get=1; assert(getter(4,4,0)==-EFAULT); cases++;
    reset(); fail_put=1; assert(getter(4,4,0)==-EFAULT); cases++;
    reset(); fail_write=1; assert(getter(4,4,0)==-EFAULT); cases++;
    reset(); behavior=BAD_RETVAL; assert(getter(4,4,-EINVAL)==-EFAULT); cases++;
    reset(); behavior=ZERO_LENGTH; assert(setter(8192,&output)==0 && !output && !live_allocations);
    assert(getter(8192,8192,0)==0 && !live_allocations); cases+=2;
    reset(); behavior=ALTER;
    char buffer[16]={0}; int len=16,level=1,name=2;
    assert(__cgroup_bpf_run_filter_setsockopt(&socket_fixture,&level,&name,buffer,&len,(char **)&output)==0);
    assert(output && len==4 && level==6 && name==9 && live_allocations==1);
    assert(((unsigned char *)output)[0]==0x5a); kfree(output); output=NULL; cases++;
    len=16;
    assert(__cgroup_bpf_run_filter_getsockopt(&socket_fixture,1,2,buffer,&len,16,0)==0);
    assert(len==4 && (unsigned char)buffer[0]==0x5a && !live_allocations); cases++;
    reset(); assert(getter(0,0,0)==0 && !live_allocations); cases++;
    assert(!live_allocations);
    printf("{\"boundary_and_failure_cases\":%d,\"passed\":true}\n",cases);
    return 0;
}
'''

with tempfile.TemporaryDirectory(prefix='borealis-bpf-sockopt-') as temporary:
    directory = Path(temporary)
    harness = directory / 'sockopt-test.c'
    harness.write_text(prefix + main)
    binary = directory / 'sockopt-test'
    subprocess.run(['gcc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', str(harness), '-o', str(binary)], check=True)
    result = json.loads(subprocess.check_output([str(binary)], text=True))
    abi = directory / 'abi.c'
    abi.write_text('typedef unsigned long long __u64; typedef int __s32;\n'
                  '#define __bpf_md_ptr(type, name) union { type name; __u64 :64; } __attribute__((aligned(8)))\n'
                  + ctx + '\n_Static_assert(sizeof(struct bpf_sockopt)==40,"size");\n'
                  '_Static_assert(__builtin_offsetof(struct bpf_sockopt,optval)==8,"ptr");\n'
                  '_Static_assert(__builtin_offsetof(struct bpf_sockopt,level)==24,"level");\n'
                  '_Static_assert(__builtin_offsetof(struct bpf_sockopt,retval)==36,"retval");\n')
    clang = '/home/android/nebula-kernel-v1.0/toolchain/bin/clang'
    for target in ('aarch64-linux-gnu', 'armv7-linux-gnueabi'):
        subprocess.run([clang, '-target', target, '-std=gnu11', '-nostdinc', '-fsyntax-only', str(abi)], check=True)
report = {'scope': 'Actual C backport functions with simulated kernel plumbing; no loaded BPF/device proof',
          **result, 'asan_ubsan': 'passed', 'uapi_layout_arm32_arm64': 'passed',
          'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
          'full_android17_compatibility': False, 'device_tested': False}
(package / 'validation/bpf-sockopt-tests.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
