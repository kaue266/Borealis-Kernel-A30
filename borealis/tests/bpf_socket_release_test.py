#!/usr/bin/env python3
"""Exercise installed release/argument-policy C with mocked network plumbing.

Real functions/macros are extracted from R24U, including both release paths
and the verifier call site. These are host sanitizer checks, not loaded BPF,
real socket concurrency, Android boot, or actual network tests.
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
names = ['include/uapi/linux/bpf.h', 'include/linux/bpf.h', 'include/linux/bpf-cgroup.h',
         'kernel/bpf/verifier.c', 'kernel/bpf/syscall.c', 'kernel/bpf/cgroup.c',
         'net/core/filter.c', 'net/ipv4/af_inet.c', 'net/ipv6/af_inet6.c']
sources = {n: (kernel / n).read_text() for n in names}

def function(text, name):
    match = re.search(r'^(?:static\s+)?(?:int|void|bool|u32|u64)\s+' + name + r'\([^;{}]*?\)\s*\{', text, re.M)
    assert match, name
    end = text.index('{', match.start()) + 1
    depth = 1
    while depth:
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        end += 1
    return text[match.start():end]

def block(text, start, finish):
    return text[text.index(start):text.index(finish, text.index(start))]

uapi = sources[names[0]]
prefix = r'''
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
typedef uint32_t u32;
typedef uint64_t u64;
typedef uint32_t __u32;
typedef int32_t __s32;
#define verbose(...) ((void)0)
#define U64_MAX UINT64_MAX
#define S64_MIN INT64_MIN
#define S64_MAX INT64_MAX
#define WARN_ON_ONCE(x) assert(!(x))
#define BPF_MAX_VAR_SIZ (1U<<29)
#define bpf_ctx_range(t,m) offsetof(t,m) ... offsetof(t,m)+sizeof(((t*)0)->m)-1
#define bpf_ctx_range_till(t,a,b) offsetof(t,a) ... offsetof(t,b)+sizeof(((t*)0)->b)-1
#define bpf_ctx_record_field_size(i,n) ((i)->ctx_field_size=(n))
struct tnum { uint64_t value, mask; };
static bool tnum_is_const(struct tnum n) { return !n.mask; }
static bool tnum_is_unknown(struct tnum n) { return n.mask==UINT64_MAX && !n.value; }
static bool tnum_in(struct tnum a,struct tnum b) { return !(b.mask&~a.mask) && !((a.value^b.value)&~a.mask); }
struct bpf_map { int key_size,value_size; };
'''
for name, text in [('bpf_arg_type', sources[names[1]]), ('bpf_reg_type', sources[names[1]]),
                   ('bpf_attach_type', uapi), ('bpf_prog_type', uapi)]:
    prefix += re.search(r'enum ' + name + r' \{.*?\};', text, re.S).group() + '\n'
prefix += re.search(r'struct bpf_sock \{.*?\n\};', uapi, re.S).group() + '\n'
prefix += r'''
enum bpf_access_type { BPF_READ=1,BPF_WRITE=2 };
#define MAX_BPF_ATTACH_TYPE __MAX_BPF_ATTACH_TYPE
struct sock;
enum bpf_func_id { BPF_FUNC_get_socket_cookie=46,BPF_FUNC_get_socket_uid=47,
    BPF_FUNC_get_current_uid_gid=15,BPF_FUNC_map_delete_elem=3 };
struct bpf_func_proto { u64 (*func)(struct sock*);bool gpl_only;int ret_type;enum bpf_arg_type arg1_type; };
#define RET_INTEGER 0
struct bpf_reg_state { enum bpf_reg_type type;int off;struct tnum var_off;
    int id,range;int64_t smin_value,smax_value;uint64_t umin_value,umax_value;struct bpf_map *map_ptr; };
struct idpair { int old,current; };
static bool range_within(struct bpf_reg_state *a,struct bpf_reg_state *b) {
    return a->umin_value<=b->umin_value && a->umax_value>=b->umax_value &&
        a->smin_value<=b->smin_value && a->smax_value>=b->smax_value;
}
static bool check_ids(int a,int b,struct idpair *m) { return a==b; }
struct bpf_prog { enum bpf_prog_type type;enum bpf_attach_type expected_attach_type;
    u32 (*run)(struct bpf_prog*,struct sock*);int id; };
struct bpf_access_dummy { int unused; };
struct bpf_insn_access_aux { int ctx_field_size; };
struct bpf_verifier_env { struct { struct bpf_reg_state regs[11]; } cur_state;
    bool allow_ptr_leaks;struct bpf_prog *prog; };
struct bpf_call_arg_meta { bool raw_mode;struct bpf_map *map_ptr; };
static bool is_pointer_value(struct bpf_verifier_env *e,int r) {
    return e->cur_state.regs[r].type!=NOT_INIT && e->cur_state.regs[r].type!=SCALAR_VALUE;
}
#define register_is_null(r) ((r).type==SCALAR_VALUE && tnum_is_const((r).var_off) && !(r).var_off.value)
static bool may_access_direct_pkt_data(struct bpf_verifier_env *e,struct bpf_call_arg_meta *m,int t) { return false; }
static int check_packet_access(struct bpf_verifier_env *e,int r,int o,int s) { assert(false);return -EFAULT; }
static int check_stack_boundary(struct bpf_verifier_env *e,int r,int s,bool z,struct bpf_call_arg_meta *m) { assert(false);return -EFAULT; }
static int check_helper_mem_access(struct bpf_verifier_env *e,int r,int s,bool z,struct bpf_call_arg_meta *m) { assert(false);return -EFAULT; }
static bool bpf_ctx_narrow_access_ok(int off,int size,int field) {
    return (size==1||size==2||size==4) && (off&(field-1))+size<=field;
}
'''
for name in ['bpf_sock_ctx_reg_is_unmodified', 'bpf_sock_reg_is_unmodified', 'check_func_arg', 'regsafe']:
    prefix += function(sources['kernel/bpf/verifier.c'], name) + '\n'
for name in ['bpf_prog_load_check_attach_type', 'bpf_prog_attach_check_attach_type']:
    prefix += function(sources['kernel/bpf/syscall.c'], name) + '\n'
for name in ['__sock_filter_check_attach_type', '__sock_filter_check_size', 'sock_filter_is_valid_access']:
    prefix += function(sources['net/core/filter.c'], name) + '\n'
prefix += r'''
struct bpf_prog_array { struct bpf_prog *progs[5]; };
struct cgroup { struct { struct bpf_prog_array *effective[MAX_BPF_ATTACH_TYPE]; } bpf; };
struct net { int *user_ns; };
struct sock;
struct proto { void (*close)(struct sock*,long); };
struct sock { struct cgroup *sk_cgrp_data;struct proto *sk_prot;struct net *net;
    u64 cookie;int uid;long sk_lingertime;bool linger,alive; };
struct socket { struct sock *sk; };
typedef int kuid_t;
static int sequence,hooks,closed,dropped,untagged,mc6,ac6,rcu_depth,delete_calls,cookie_reads;
static int hook_order,drop_order,close_order;
static long observed_timeout;
static struct socket *active;
static struct { unsigned flags; } current_state;
#define current (&current_state)
#define PF_EXITING 4
#define SOCK_LINGER 1
#define sock_flag(s,f) ((s)->linger)
static bool cgroup_bpf_enabled;
static struct cgroup *sock_cgroup_ptr(struct cgroup **p) { return *p; }
static void rcu_read_lock(void) { rcu_depth++; }
static void rcu_read_unlock(void) { assert(rcu_depth>0);rcu_depth--; }
#define rcu_dereference(p) (p)
#define READ_ONCE(p) (p)
#define unlikely(p) (p)
#define BPF_PROG_RUN(p,c) ((p)->run(p,c))
#define EXPORT_SYMBOL(n)
#define BPF_CALL_1(n,t,a) static u64 n(t a)
static struct net *sock_net(struct sock *s) { assert(s->alive);return s->net; }
static kuid_t sock_net_uid(struct net *n,struct sock *s) { assert(s->alive && n==s->net);return s->uid; }
static u32 from_kuid_munged(int *ns,kuid_t id) { return *ns+id; }
static u64 bpf_get_socket_cookie_sock(struct sock *s) {
    assert(s->alive && s==active->sk);cookie_reads++;if(!s->cookie)s->cookie=0xabcdef;return s->cookie;
}
static const struct bpf_func_proto generic_proto={.arg1_type=ARG_ANYTHING};
static const struct bpf_func_proto *bpf_base_func_proto(enum bpf_func_id id) { return &generic_proto; }
static void ip_mc_drop_socket(struct sock *s) { assert(s->alive);dropped++;drop_order=++sequence; }
static void qtaguid_untag(struct socket *s,bool closing) { assert(s->sk->alive && closing);untagged++; }
static void ipv6_sock_mc_close(struct sock *s) { assert(s->alive);mc6++; }
static void ipv6_sock_ac_close(struct sock *s) { assert(s->alive);ac6++; }
'''
prefix += block(sources[names[1]], '#define __BPF_PROG_RUN_ARRAY', '#ifdef CONFIG_BPF_SYSCALL')
prefix += (package / 'kernel-patches/release-filter.c').read_text() + '\n'
assert (package / 'kernel-patches/release-filter.c').read_text().strip() in sources['net/core/filter.c']
prefix += function(sources['kernel/bpf/cgroup.c'], '__cgroup_bpf_run_sock_release') + '\n'
header = sources['include/linux/bpf-cgroup.h']
enabled = block(header, '#define BPF_CGROUP_RUN_PROG_INET_SOCK_RELEASE(sk)', '#define BPF_CGROUP_RUN_PROG_INET_SOCK(sk)')
disabled = re.findall(r'^#define BPF_CGROUP_RUN_PROG_INET_SOCK_RELEASE\(sk\) do \{ \} while \(0\)$', header, re.M)[0]
prefix += '#if TEST_CGROUP\n' + enabled + '\n#else\n' + disabled + '\n#endif\n'
prefix += function(sources['net/ipv4/af_inet.c'], 'inet_release') + '\n'
prefix += function(sources['net/ipv6/af_inet6.c'], 'inet6_release') + '\n'

main = r'''
static int cases;
static void close_proto(struct sock *s,long timeout) {
    assert(s->alive && active->sk==NULL && !rcu_depth);
    assert(drop_order>0);s->alive=false;closed++;close_order=++sequence;observed_timeout=timeout;
}
static u32 run_prog(struct bpf_prog *p,struct sock *s) {
    assert(rcu_depth>0 && s->alive && active->sk==s && !closed);
    if(p->id==-1)return 1; /* R24U deleted-program dummy */
    hooks++;hook_order=++sequence;
    const struct bpf_func_proto *f=cg_sock_func_proto(BPF_FUNC_get_socket_cookie,p);
    assert(f->arg1_type==ARG_PTR_TO_SOCK_CTX);
    u64 cookie=f->func(s);assert(cookie!=0);delete_calls++;
    return p->id==0 ? 0 : 1;
}
static void guard_tests(void) {
    struct bpf_prog prog={.type=BPF_PROG_TYPE_CGROUP_SOCK,.expected_attach_type=BPF_CGROUP_INET_SOCK_RELEASE};
    struct bpf_verifier_env e={.prog=&prog};struct bpf_call_arg_meta meta={0};
    struct bpf_reg_state base={.type=PTR_TO_CTX};
    for(int type=NOT_INIT;type<=PTR_TO_SOCKET;type++) {
        e.cur_state.regs[1]=base;e.cur_state.regs[1].type=type;
        assert((check_func_arg(&e,1,ARG_PTR_TO_SOCK_CTX,&meta)==0)==(type==PTR_TO_CTX));cases++;
    }
    for(int field=0;field<7;field++)for(int v=-2;v<=2;v++) {
        struct bpf_reg_state *r=&e.cur_state.regs[1];*r=base;
        switch(field) {
        case 0:r->off=v;break;case 1:r->var_off.value=v;break;case 2:r->var_off.mask=v;break;
        case 3:r->smin_value=v;break;case 4:r->smax_value=v;break;
        case 5:r->umin_value=v;break;case 6:r->umax_value=v;break;
        }
        assert((check_func_arg(&e,1,ARG_PTR_TO_SOCK_CTX,&meta)==0)==(v==0));cases++;
    }
    struct bpf_reg_state scalar={.type=SCALAR_VALUE,.smin_value=INT64_MIN,.smax_value=INT64_MAX,
        .umin_value=0,.umax_value=UINT64_MAX,.var_off={.mask=UINT64_MAX}};
    struct idpair ids={0};
    assert(!regsafe(&scalar,&base,false,&ids));cases++;
    assert(!regsafe(&scalar,&base,true,&ids));cases++;
    assert(regsafe(&base,&base,false,&ids));cases++;
    struct bpf_reg_state unused={0};assert(regsafe(&unused,&base,false,&ids));cases++;
    e.cur_state.regs[1]=base;assert(check_func_arg(&e,1,ARG_ANYTHING,&meta)==-EACCES);cases++;
    assert(check_func_arg(&e,1,ARG_PTR_TO_SOCKET,&meta)==-EACCES);cases++;
    for(int off=-8;off<89;off++)for(int size=0;size<=8;size++)for(int type=0;type<3;type++) {
        struct bpf_insn_access_aux info={0};
        bool allowed=type==BPF_READ && size==4 && off>=0 && off<=76 && !(off&3);
        assert(sock_filter_is_valid_access(off,size,type,&prog,&info)==allowed);
        if(allowed)assert(info.ctx_field_size==4);cases++;
    }
    prog.expected_attach_type=BPF_CGROUP_INET_SOCK_CREATE;
    struct bpf_insn_access_aux info={0};
    assert(sock_filter_is_valid_access(offsetof(struct bpf_sock,mark),4,BPF_WRITE,&prog,&info));cases++;
    prog.expected_attach_type=BPF_CGROUP_INET4_POST_BIND;
    assert(!sock_filter_is_valid_access(offsetof(struct bpf_sock,mark),4,BPF_WRITE,&prog,&info));cases++;
    assert(sock_filter_is_valid_access(offsetof(struct bpf_sock,src_ip4),4,BPF_READ,&prog,&info));cases++;
    for(int attach=0;attach<MAX_BPF_ATTACH_TYPE+2;attach++) {
        bool allowed=attach==BPF_CGROUP_INET_SOCK_CREATE || attach==BPF_CGROUP_INET4_POST_BIND ||
            attach==BPF_CGROUP_INET6_POST_BIND || attach==BPF_CGROUP_INET_SOCK_RELEASE;
        assert((bpf_prog_load_check_attach_type(BPF_PROG_TYPE_CGROUP_SOCK,attach)==0)==allowed);cases++;
        prog.expected_attach_type=BPF_CGROUP_INET_SOCK_RELEASE;
        assert((bpf_prog_attach_check_attach_type(&prog,attach)==0)==(attach==BPF_CGROUP_INET_SOCK_RELEASE));cases++;
    }
}
static void release_tests(void) {
    struct proto protocol={.close=close_proto};int ns=4000;struct net net={.user_ns=&ns};
    for(int v6=0;v6<2;v6++)for(int enabled=0;enabled<2;enabled++)for(int arr=0;arr<4;arr++)
    for(int linger=0;linger<2;linger++)for(int exiting=0;exiting<2;exiting++) {
        struct cgroup cg={0};struct bpf_prog_array array={0};
        struct bpf_prog progs[3]={{.run=run_prog,.id=0},{.run=run_prog,.id=1},{.run=run_prog,.id=-1}};
        if(arr!=0)cg.bpf.effective[BPF_CGROUP_INET_SOCK_RELEASE]=&array;
        if(arr==2)array.progs[0]=&progs[2];
        if(arr==3) { array.progs[0]=&progs[0];array.progs[1]=&progs[2];array.progs[2]=&progs[1]; }
        struct sock s={.sk_cgrp_data=&cg,.sk_prot=&protocol,.net=&net,.alive=true,
            .uid=123,.linger=linger,.sk_lingertime=17};struct socket sock={.sk=&s};active=&sock;
        cgroup_bpf_enabled=enabled;current_state.flags=exiting?PF_EXITING:0;
        sequence=hooks=closed=dropped=untagged=mc6=ac6=rcu_depth=delete_calls=cookie_reads=0;
        hook_order=drop_order=close_order=0;
        assert((v6?inet6_release(&sock):inet_release(&sock))==0);
        assert(closed==1 && dropped==1 && !s.alive && sock.sk==NULL && !rcu_depth);
        assert(mc6==v6 && ac6==v6 && observed_timeout==(linger&&!exiting?17:0));
        int expected=(TEST_CGROUP && enabled && arr==3)?2:0;
        assert(hooks==expected && delete_calls==expected && cookie_reads==expected);
        if(expected)assert(hook_order<drop_order && drop_order<close_order);
        assert(untagged==TEST_QTAGUID);
        assert(inet_release(&sock)==0 && closed==1);
        assert(inet6_release(&sock)==-EINVAL && closed==1);cases++;
    }
    struct sock s={.alive=true,.net=&net,.uid=123};struct socket sock={.sk=&s};active=&sock;
    const struct bpf_func_proto *cookie=cg_sock_func_proto(BPF_FUNC_get_socket_cookie,NULL);
    const struct bpf_func_proto *uid=cg_sock_func_proto(BPF_FUNC_get_socket_uid,NULL);
    assert(cookie->func==bpf_get_socket_cookie_sock && cookie->arg1_type==ARG_PTR_TO_SOCK_CTX);cases++;
    assert(uid->func(&s)==4123 && uid->arg1_type==ARG_PTR_TO_SOCK_CTX);cases++;
    assert(cg_sock_func_proto(BPF_FUNC_get_current_uid_gid,NULL)==&generic_proto);cases++;
    assert(cg_sock_func_proto(BPF_FUNC_map_delete_elem,NULL)==&generic_proto);cases++;
}
int main(void) {
    _Static_assert(BPF_CGROUP_INET_SOCK_RELEASE==23,"release ABI");
    _Static_assert(BPF_CGROUP_GETSOCKOPT==21 && BPF_CGROUP_SETSOCKOPT==22,"sockopt ABI");
    guard_tests();release_tests();printf("{\"cases\":%d,\"passed\":true}\n",cases);return 0;
}
'''
# Preserve real attach/detach/query routing and shared IPv6 release semantics.
for name in ['bpf_prog_attach', 'bpf_prog_detach', 'bpf_prog_query']:
    body = function(sources['kernel/bpf/syscall.c'], name)
    assert body.count('case BPF_CGROUP_INET_SOCK_RELEASE:') == 1
assert function(sources['net/ipv6/af_inet6.c'], 'inet6_release').count('inet_release(sock)') == 1
assert 'INET_SOCK_RELEASE' not in function(sources['net/ipv6/af_inet6.c'], 'inet6_release')
assert '.get_func_proto\t\t= cg_sock_func_proto,' in sources['net/core/filter.c']
reference = package / 'validation/bpf-reference/linux-v5.10'
assert 'BPF_CGROUP_RUN_PROG_INET_SOCK_RELEASE(sk)' in function((reference / 'net/ipv4/af_inet.c').read_text(), 'inet_release')
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
variants = {}
with tempfile.TemporaryDirectory(prefix='borealis-bpf-release-') as temp:
    directory = Path(temp)
    harness = directory / 'release.c'
    harness.write_text(prefix + main)
    for cgroup in (0, 1):
        for qtaguid in (0, 1):
            binary = directory / f'cg{cgroup}-qtaguid{qtaguid}'
            definitions = [f'-DTEST_CGROUP={cgroup}', f'-DTEST_QTAGUID={qtaguid}']
            if qtaguid: definitions += ['-DCONFIG_NETFILTER_XT_MATCH_QTAGUID']
            subprocess.run(['gcc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                            '-fno-omit-frame-pointer', '-no-pie', *definitions, str(harness), '-o', str(binary)], check=True)
            variants[binary.name] = json.loads(subprocess.check_output([str(binary)], text=True))
    old_guard = '\tif (rcur->type == PTR_TO_CTX && rold->type != PTR_TO_CTX)\n\t\treturn false;\n'
    assert prefix.count(old_guard) == 1
    regression = directory / 'context-pruning-before.c'
    regression.write_text(prefix.replace(old_guard, '', 1) + main)
    binary = directory / 'context-pruning-before'
    subprocess.run(['gcc', '-std=gnu11', '-O1', '-DTEST_CGROUP=1', '-DTEST_QTAGUID=0',
                    str(regression), '-o', str(binary)], check=True)
    failure = subprocess.run([str(binary)], capture_output=True, text=True)
    assert failure.returncode != 0 and '!regsafe(&scalar,&base' in failure.stderr

report = {'scope': 'Installed C release paths, argument checks, program-array macro and policy with mock sockets/RCU/maps',
          'variants': variants, 'cases': sum(r['cases'] for r in variants.values()),
          'asan_ubsan': 'passed', 'pre_fix_context_pruning_regression_reproduced': True,
          'source_sha256': {n: hashlib.sha256(s.encode()).hexdigest() for n, s in sources.items()},
          'device_tested': False, 'real_socket_concurrency_tested': False,
          'loaded_bpf_programs_tested': False, 'android17_network_validated': False}
(package / 'validation/bpf-socket-release-tests.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
