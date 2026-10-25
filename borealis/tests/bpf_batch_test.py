#!/usr/bin/env python3
"""Test the actual batch functions with fault injection and sanitizers."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import tempfile

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
htab = (kernel / 'kernel/bpf/hashtab.c').read_text()
syscall = (kernel / 'kernel/bpf/syscall.c').read_text()
header = (kernel / 'include/uapi/linux/bpf.h').read_text()
snippets = {}
for filename, installed in [('batch-htab.c', htab), ('batch-array.c', syscall), ('batch-syscall.c', syscall)]:
    snippet = (package / 'kernel-patches' / filename).read_text()
    assert installed.count(snippet) == 1, 'Test must execute the exact installed source'
    snippets[filename] = snippet
batch_abi = re.search(r'struct \{ /\* Standard batch lookup ABI.*?\} batch;', header, re.S).group()
enums = re.search(r'enum bpf_cmd \{.*?\};', header, re.S).group()
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
typedef uint32_t u32;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef uint64_t __aligned_u64 __attribute__((aligned(8)));
#define __user
#define __percpu
#define GFP_USER 0
#define __GFP_NOWARN 0
#define ENOTSUPP 524
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define round_up(x,a) (((x)+(a)-1)&~((typeof(x))(a)-1))
#define u64_to_user_ptr(x) ((void *)(uintptr_t)(x))
#define PTR_ERR(x) ((int)(intptr_t)(x))
#define IS_ERR(x) ((uintptr_t)(x) >= (uintptr_t)-4095)
#define BPF_MAP_TYPE_ARRAY 2
#define BPF_MAP_TYPE_PERCPU_ARRAY 6
#define FMODE_CAN_READ 1
#define FMODE_CAN_WRITE 2
'''
prefix += enums + '\nunion bpf_attr {' + batch_abi + '};\n' + r'''
struct bpf_map;
struct bpf_map_ops {
 void *(*map_lookup_elem)(struct bpf_map *,void *);
 int (*map_lookup_batch)(struct bpf_map *,const union bpf_attr *,union bpf_attr *);
 int (*map_lookup_and_delete_batch)(struct bpf_map *,const union bpf_attr *,union bpf_attr *);
};
struct bpf_map { u32 key_size,value_size,max_entries,map_type; const struct bpf_map_ops *ops; };
struct hlist_nulls_node { struct hlist_nulls_node *next,**pprev; };
struct hlist_nulls_head { struct hlist_nulls_node *first; };
struct htab_elem;
struct lru_node { struct htab_elem *owner; };
struct htab_elem { struct hlist_nulls_node hash_node; struct lru_node lru_node; unsigned char key[256] __attribute__((aligned(8))); };
struct bucket { struct hlist_nulls_head head; int lock; };
struct bpf_htab { struct bpf_map map; struct bucket buckets[3]; int lru; u32 n_buckets; };
static int preempt_depth,rcu_depth,lock_depth,active,live_allocs,alloc_calls,fail_alloc;
static int fail_read,fail_copy,copy_calls,fail_put,put_calls,fd_gets,fd_puts,fd_invalid;
static int cpu_count=4,lru_map,percpu_map,cases,deleted_count;
static struct bpf_htab table;
static unsigned char array_values[8][64];
static struct { int f_mode; } file_fixture;
struct fd { typeof(file_fixture) *file; };
#define CHECK_ATTR(x) (bad_tail)
static int bad_tail;
static int num_possible_cpus(void) { return cpu_count; }
#define for_each_possible_cpu(c) for(c=0;c<cpu_count;c++)
static bool htab_is_percpu(struct bpf_htab *x) { return percpu_map; }
static bool htab_is_lru(struct bpf_htab *x) { return lru_map; }
static int is_a_nulls(struct hlist_nulls_node *node) { return (uintptr_t)node&1; }
#define hlist_nulls_entry(n,t,m) container_of(n,t,m)
#define rcu_dereference_raw(x) (x)
#define hlist_nulls_for_each_entry_rcu(e,n,h,m) \
 for(n=(h)->first;!is_a_nulls(n)&&((e)=hlist_nulls_entry(n,struct htab_elem,m),1);n=n->next)
static void hlist_nulls_del_rcu(struct hlist_nulls_node *node) {
 assert(lock_depth==1&&rcu_depth==1); *node->pprev=node->next;
 if(!is_a_nulls(node->next)) node->next->pprev=node->pprev;
}
static void *htab_elem_get_ptr(struct htab_elem *e,u32 key_size) {
 void *ptr; memcpy(&ptr,e->key+key_size,sizeof(ptr)); return ptr;
}
static void *per_cpu_ptr(void *ptr,int cpu) { return (char *)ptr+cpu*round_up((size_t)table.map.value_size,8); }
static void free_element(struct htab_elem *e) {
 if(percpu_map) free(htab_elem_get_ptr(e,table.map.key_size)); free(e); deleted_count++;
}
static void free_htab_elem(struct bpf_htab *h,struct htab_elem *e) { assert(lock_depth==1); free_element(e); }
static void bpf_lru_push_free(int *lru,struct lru_node *node) { assert(lock_depth==0); free_element(node->owner); }
#define bpf_long_memcpy(d,s,n) memcpy(d,s,n)
#define preempt_disable() (++preempt_depth)
#define preempt_enable() (--preempt_depth)
#define bpf_prog_active active
#define this_cpu_inc(x) (++(x))
#define this_cpu_dec(x) (--(x))
#define rcu_read_lock() (++rcu_depth)
#define rcu_read_unlock() (--rcu_depth)
#define raw_spin_lock_irqsave(x,f) do { assert(!lock_depth); lock_depth++; f=0; } while(0)
#define raw_spin_unlock_irqrestore(x,f) do { assert(lock_depth==1); lock_depth--; } while(0)
static void *kmalloc(size_t size,int flags) {
 assert(!lock_depth&&!rcu_depth); alloc_calls++;
 if(alloc_calls==fail_alloc) return NULL;
 void *p=malloc(size); assert(p); live_allocs++; return p;
}
static void *kmalloc_array(size_t n,size_t size,int flags) {
 if(size&&n>SIZE_MAX/size) return NULL; return kmalloc(n*size,flags);
}
static void kfree(void *p) { if(p) { free(p); live_allocs--; } }
static int copy_from_user(void *d,const void *s,size_t n) {
 assert(!lock_depth&&!rcu_depth); if(fail_read||!s) return 1; memcpy(d,s,n); return 0;
}
static int copy_to_user(void *d,const void *s,size_t n) {
 assert(!lock_depth&&!rcu_depth); copy_calls++; if(copy_calls==fail_copy||!d) return 1; memcpy(d,s,n); return 0;
}
static int put_value(u32 v,u32 *p) {
 assert(!lock_depth&&!rcu_depth); put_calls++; if(put_calls==fail_put||!p) return 1; *p=v; return 0;
}
#define put_user(v,p) put_value(v,p)
static void *array_lookup(struct bpf_map *m,void *key) {
 u32 k=*(u32 *)key; return k<m->max_entries?array_values[k]:NULL;
}
static int bpf_percpu_array_copy(struct bpf_map *m,void *key,void *value) {
 void *ptr=array_lookup(m,key); if(!ptr) return -ENOENT;
 memcpy(value,ptr,round_up((size_t)m->value_size,8)*cpu_count); return 0;
}
static struct fd fdget(u32 fd) { if(fd_invalid!=1)fd_gets++; return (struct fd){ fd_invalid==1?NULL:&file_fixture }; }
static void fdput(struct fd fd) { if(fd.file)fd_puts++; }
static struct bpf_map *__bpf_map_get(struct fd fd) {
 if(!fd.file)return (void *)(intptr_t)-EBADF;
 /* Exact R24U ownership rule: the helper releases non-BPF descriptors. */
 if(fd_invalid==2){fdput(fd);return (void *)(intptr_t)-EINVAL;}
 return &table.map;
}
'''
main = r'''
static const struct bpf_map_ops hash_ops={ .map_lookup_batch=htab_map_lookup_batch,
 .map_lookup_and_delete_batch=htab_map_lookup_and_delete_batch };
static const struct bpf_map_ops array_ops={ .map_lookup_elem=array_lookup,.map_lookup_batch=bpf_array_lookup_batch };
static void reset(void) {
 assert(!live_allocs&&!lock_depth&&!rcu_depth&&!preempt_depth&&!active);
 memset(&table,0,sizeof(table)); table.n_buckets=3;
 for(int b=0;b<3;b++) table.buckets[b].head.first=(void *)1;
 alloc_calls=copy_calls=put_calls=deleted_count=0;
 fail_alloc=fail_read=fail_copy=fail_put=bad_tail=fd_invalid=0; fd_gets=fd_puts=0;
 file_fixture.f_mode=3;
}
static void add_element(u32 id,int bucket) {
 struct htab_elem *e=calloc(1,sizeof(*e)); assert(e); e->lru_node.owner=e;
 memset(e->key,(unsigned char)(id+1),table.map.key_size);
 if(percpu_map) {
  size_t sz=round_up((size_t)table.map.value_size,8)*cpu_count;
  void *p=malloc(sz); assert(p); memset(p,(unsigned char)(id+17),sz);
  memcpy(e->key+table.map.key_size,&p,sizeof(p));
 } else memset(e->key+round_up(table.map.key_size,8),(unsigned char)(id+17),table.map.value_size);
 struct hlist_nulls_head *head=&table.buckets[bucket].head;
 e->hash_node.next=head->first; e->hash_node.pprev=&head->first;
 if(!is_a_nulls(head->first)) head->first->pprev=&e->hash_node.next; head->first=&e->hash_node;
}
static void clear_table(void) {
 for(int b=0;b<3;b++) {
  struct hlist_nulls_node *n=table.buckets[b].head.first;
  while(!is_a_nulls(n)) { struct hlist_nulls_node *next=n->next; free_element(hlist_nulls_entry(n,struct htab_elem,hash_node)); n=next; }
  table.buckets[b].head.first=(void *)1;
 }
 assert(!live_allocs&&!lock_depth&&!rcu_depth&&!preempt_depth&&!active);
}
static union bpf_attr attr(u32 limit,void *keys,void *values,u32 *out,u32 *in) {
 return (union bpf_attr){ .batch={ .count=limit,.keys=(uintptr_t)keys,.values=(uintptr_t)values,
  .out_batch=(uintptr_t)out,.in_batch=(uintptr_t)in,.map_fd=7 } };
}
static void check_hashes(void) {
 const u32 key_sizes[]={3,7,8,12},value_sizes[]={3,5,9,24},nums[]={0,1,5,6,13},limits[]={1,5,20};
 for(int p=0;p<2;p++) for(int l=0;l<2;l++) for(int d=0;d<2;d++)
 for(int ks=0;ks<4;ks++) for(int vs=0;vs<4;vs++) for(int ns=0;ns<5;ns++)
 for(int li=0;li<3;li++) for(int collision=0;collision<2;collision++) {
  reset(); percpu_map=p; lru_map=l; table.map.key_size=key_sizes[ks]; table.map.value_size=value_sizes[vs];
  u32 n=nums[ns],limit=limits[li],out=99,counts[3]={0},expected=0,cursor=0;
  for(u32 i=0;i<n;i++) { int b=collision?1:i%3; counts[b]++; add_element(i,b); }
  unsigned char keys[256]={0},values[3072]={0}; union bpf_attr a=attr(limit,keys,values,&out,NULL),u=a;
  int expected_error=0;
  while(cursor<3) {
   if(counts[cursor]>limit-expected) { expected_error=expected?0:-ENOSPC; break; }
   expected+=counts[cursor++]; if(cursor==3) { expected_error=-ENOENT; break; }
   if(expected==limit) break;
  }
  int result=htab_map_batch(&table.map,&a,&u,d);
  assert(result==expected_error&&u.batch.count==expected&&out==cursor);
  assert(deleted_count==(d?expected:0));
  size_t sz=p?round_up((size_t)table.map.value_size,8)*cpu_count:table.map.value_size;
  for(u32 i=0;i<expected;i++) {
   unsigned char id=keys[(size_t)i*table.map.key_size]; assert(id>=1&&id<=n);
   for(u32 j=0;j<table.map.key_size;j++) assert(keys[(size_t)i*table.map.key_size+j]==id);
   for(size_t j=0;j<sz;j++) assert(values[(size_t)i*sz+j]==(unsigned char)(id+16));
  }
  clear_table(); cases++;
 }
}
static void check_faults(void) {
 unsigned char keys[512],values[2048]; u32 out=0,in=0;
 for(int l=0;l<2;l++) for(int del=0;del<2;del++) for(int fault=1;fault<=9;fault++) {
  reset(); percpu_map=0;lru_map=l; table.map.key_size=7;table.map.value_size=9;
  for(int i=0;i<6;i++) add_element(i,1);
  union bpf_attr a=attr(20,keys,values,&out,&in),u=a;
  if(fault<=3) fail_alloc=fault;
  if(fault==4) fail_read=1;
  if(fault>=5&&fault<=7) fail_copy=fault-4;
  if(fault>=8) fail_put=fault-7;
  int ret=htab_map_batch(&table.map,&a,&u,del);
  assert(ret<0); clear_table(); cases++;
 }
 reset();percpu_map=1;lru_map=0;table.map.key_size=7;table.map.value_size=UINT_MAX;
 union bpf_attr a=attr(UINT_MAX,keys,values,&out,NULL),u=a;
 assert(htab_map_batch(&table.map,&a,&u,0)==-E2BIG&&!alloc_calls);cases++;
 reset();percpu_map=0;lru_map=0;table.map.key_size=7;table.map.value_size=9;
 a=attr(0,NULL,NULL,NULL,NULL);u=a;assert(!htab_map_batch(&table.map,&a,&u,0)&&!alloc_calls&&!put_calls);cases++;
 a.batch.flags=1;assert(htab_map_batch(&table.map,&a,&u,0)==-EINVAL);cases++;
 a.batch.flags=0;a.batch.elem_flags=4;assert(htab_map_batch(&table.map,&a,&u,0)==-EINVAL);cases++;
 a=attr(5,keys,values,&out,&in);u=a;in=UINT_MAX;
 assert(htab_map_batch(&table.map,&a,&u,0)==-ENOENT&&u.batch.count==0&&!alloc_calls);cases++;
}
static void check_arrays(void) {
 for(int p=0;p<2;p++) for(u32 size=1;size<=13;size+=4) for(u32 limit=1;limit<=12;limit++)
 for(int start=-1;start<=8;start++) {
  reset();table.map=(struct bpf_map){.key_size=4,.value_size=size,.max_entries=8,
   .map_type=p?BPF_MAP_TYPE_PERCPU_ARRAY:BPF_MAP_TYPE_ARRAY,.ops=&array_ops};
  size_t sz=p?round_up((size_t)size,8)*cpu_count:size;
  for(int i=0;i<8;i++) memset(array_values[i],i+20,sz);
  u32 in=start,out=99,keys[16]={0};unsigned char values[1024]={0};
  union bpf_attr a=attr(limit,keys,values,&out,start<0?NULL:&in),u=a;
  u32 first=start<0||start>=8?0:start+1,expected=first>=8?0:(limit<8-first?limit:8-first);
  int ret=bpf_array_lookup_batch(&table.map,&a,&u);
  assert(ret==(limit>8-first?-ENOENT:0)&&u.batch.count==expected);
  if(expected) assert(out==first+expected-1);else assert(out==99);
  for(u32 i=0;i<expected;i++) {assert(keys[i]==first+i);for(size_t j=0;j<sz;j++)assert(values[i*sz+j]==first+i+20);}
  assert(!live_allocs);cases++;
 }
 for(int fault=1;fault<=7;fault++) {
  reset();table.map=(struct bpf_map){4,9,8,BPF_MAP_TYPE_ARRAY,&array_ops};
  u32 in=0,out=0,keys[16];unsigned char values[256];union bpf_attr a=attr(20,keys,values,&out,&in),u=a;
  if(fault==1)fail_alloc=1;if(fault==2)fail_read=1;if(fault>=3&&fault<=5)fail_copy=fault-2;if(fault>=6)fail_put=fault-5;
  assert(bpf_array_lookup_batch(&table.map,&a,&u)<0&&!live_allocs);cases++;
 }
}
static void check_dispatch(void) {
 reset();table.map.ops=&hash_ops;table.map.key_size=4;table.map.value_size=4;
 u32 keys[8],values[8],out;union bpf_attr a=attr(1,keys,values,&out,NULL),u=a;
 for(int mode=0;mode<4;mode++)for(int del=0;del<2;del++) {
  file_fixture.f_mode=mode;int gets=fd_gets,puts=fd_puts;
  int ret=bpf_map_do_batch(&a,&u,del?BPF_MAP_LOOKUP_AND_DELETE_BATCH:BPF_MAP_LOOKUP_BATCH);
  assert(ret==((mode&1)&&(!del||(mode&2))?-ENOENT:-EPERM));
  assert(fd_gets==gets+1&&fd_puts==puts+1);cases++;
 }
 fd_invalid=1;assert(bpf_map_do_batch(&a,&u,BPF_MAP_LOOKUP_BATCH)==-EBADF&&fd_gets==fd_puts);cases++;
 fd_invalid=2;assert(bpf_map_do_batch(&a,&u,BPF_MAP_LOOKUP_BATCH)==-EINVAL&&fd_gets==fd_puts);cases++;
 fd_invalid=0;file_fixture.f_mode=3;table.map.ops=&array_ops;
 assert(bpf_map_do_batch(&a,&u,BPF_MAP_LOOKUP_AND_DELETE_BATCH)==-ENOTSUPP&&fd_gets==fd_puts);cases++;
 int gets=fd_gets;bad_tail=1;assert(bpf_map_do_batch(&a,&u,BPF_MAP_LOOKUP_BATCH)==-EINVAL&&fd_gets==gets);cases++;
 bad_tail=0;a.batch.elem_flags=4;assert(bpf_map_do_batch(&a,&u,BPF_MAP_LOOKUP_BATCH)==-EINVAL&&fd_gets==gets);cases++;
}
int main(void) { check_hashes();check_faults();check_arrays();check_dispatch();
 printf("{\"boundary_and_failure_cases\":%d,\"passed\":true}\n",cases); }
'''
with tempfile.TemporaryDirectory(prefix='borealis-bpf-batch-') as temp:
    directory = Path(temp)
    harness = directory / 'batch.c'
    harness.write_text(prefix + '\n'.join(snippets.values()) + main)
    binary = directory / 'batch-test'
    subprocess.run(['gcc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                    '-fno-omit-frame-pointer', str(harness), '-o', str(binary)], check=True)
    result = json.loads(subprocess.check_output([str(binary)], text=True))
    abi = directory / 'abi.c'
    abi.write_text('typedef unsigned int __u32; typedef unsigned long long __u64;\n'
                  'typedef __u64 __aligned_u64 __attribute__((aligned(8)));\n'
                  'union bpf_attr {' + batch_abi + '};\n'
                  '_Static_assert(sizeof(((union bpf_attr*)0)->batch)==56,"size");\n'
                  '_Static_assert(__builtin_offsetof(union bpf_attr,batch.count)==32,"count");\n'
                  '_Static_assert(__builtin_offsetof(union bpf_attr,batch.map_fd)==36,"fd");\n'
                  '_Static_assert(__builtin_offsetof(union bpf_attr,batch.flags)==48,"flags");\n')
    clang = '/home/android/nebula-kernel-v1.0/toolchain/bin/clang'
    for target in ('aarch64-linux-gnu', 'armv7-linux-gnueabi'):
        subprocess.run([clang, '-target', target, '-nostdinc', '-fsyntax-only', str(abi)], check=True)
report = {'scope': 'Actual installed batch functions with simulated maps/locks; no device or concurrency proof',
          **result, 'asan_ubsan': 'passed', 'uapi_layout_arm32_arm64': 'passed',
          'function_sources': {name: hashlib.sha256(value.encode()).hexdigest() for name, value in snippets.items()},
          'full_kernel_link_passed': False, 'runtime_tested': False, 'android17_network_validated': False}
(package / 'validation/bpf-batch-tests.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
