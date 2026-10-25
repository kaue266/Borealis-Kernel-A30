#!/usr/bin/env python3
"""Test installed array allocation/mmap C with simulated VM/file plumbing."""
from pathlib import Path
import hashlib
import json
import re
import subprocess
import tempfile

package = Path(__file__).resolve().parent.parent
kernel = Path('/home/android/nebula-r24u-android17')
names = ['kernel/bpf/arraymap.c', 'kernel/bpf/syscall.c', 'include/linux/bpf.h',
         'include/uapi/linux/bpf.h', 'mm/mmap.c', 'mm/vmalloc.c']
sources = {name: (kernel / name).read_text() for name in names}


def function(text, name):
    match = re.search(r'^(?:static )?[^;{}\n]*\b' + name + r'\([^;{}]*?\)\s*\{', text, re.M)
    assert match, name
    end = text.index('{', match.start()) + 1
    depth = 1
    while depth:
        if text[end] == '{': depth += 1
        if text[end] == '}': depth -= 1
        end += 1
    return text[match.start():end]


uapi = sources['include/uapi/linux/bpf.h']
map_types = re.search(r'enum bpf_map_type \{.*?\};', uapi, re.S).group()
flags = '\n'.join(re.search(r'^#define ' + name + r'\s+.*$', uapi, re.M).group()
                  for name in ['BPF_F_NUMA_NODE', 'BPF_F_RDONLY', 'BPF_F_WRONLY', 'BPF_F_MMAPABLE'])
array_body = re.search(r'struct bpf_array \{.*?\n\};', sources['include/linux/bpf.h'], re.S).group()
prefix = flags + '\n' + r'''
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
typedef uint64_t u64;
typedef unsigned long pgoff_t;
typedef unsigned long gfp_t;
typedef unsigned long pgprot_t;
#define PAGE_SIZE (1UL<<PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE-1))
#define round_up(x,a) (((x)+(__typeof__(x))((a)-1))&~(__typeof__(x))((a)-1))
#define PAGE_ALIGN(x) round_up(x,PAGE_SIZE)
#define U32_MAX UINT32_MAX
#define NUMA_NO_NODE (-1)
#define KMALLOC_SHIFT_MAX 22
#define PCPU_MIN_UNIT_SIZE (32*1024)
#define CAP_SYS_ADMIN 1
#define ERR_PTR(x) ((void *)(intptr_t)(x))
#define IS_ERR(x) ((uintptr_t)(x)>=(uintptr_t)-4095)
#define PTR_ERR(x) ((int)(intptr_t)(x))
#define __aligned(x) __attribute__((aligned(x)))
#define __percpu
#define container_of(p,t,m) ((t *)((char *)(p)-offsetof(t,m)))
#define GFP_USER 0x001
#define __GFP_NOWARN 0x002
#define __GFP_NORETRY 0x004
#define __GFP_ZERO 0x008
#define PAGE_KERNEL 0x010
#define VM_USERMAP 0x020
#define VMALLOC_START 0x1000
#define VMALLOC_END ULONG_MAX
#define VM_SHARED 0x001
#define VM_READ 0x002
#define VM_WRITE 0x004
#define VM_EXEC 0x008
#define VM_MAYWRITE 0x010
#define VM_MAYEXEC 0x020
#define VM_DONTDUMP 0x040
#define VM_DONTEXPAND 0x080
#define FMODE_READ 1
#define FMODE_WRITE 2
enum bpf_prog_type { BPF_PROG_TYPE_TEST };
struct bpf_map;
struct vm_area_struct;
struct bpf_map_ops { int (*map_mmap)(struct bpf_map *,struct vm_area_struct *); };
struct bpf_map { u32 map_type,key_size,value_size,max_entries,map_flags,pages;
    int numa_node; bool unpriv_array; const struct bpf_map_ops *ops; };
struct file { void *private_data; int f_mode, references; };
struct vm_area_struct { unsigned long vm_start,vm_end,vm_flags,vm_pgoff;
    struct file *vm_file; unsigned char *mapped; };
union bpf_attr { struct {u32 map_type,key_size,value_size,max_entries,map_flags;int numa_node;}; };
static bool admin=true;
static int fail_alloc,fail_charge,fail_percpu,fail_remap,allocations,frees,precharges,percpu_frees;
static struct {void *base;size_t bytes;bool usermap;} blocks[16];
static int bpf_map_attr_numa_node(union bpf_attr *a) { return a->map_flags&BPF_F_NUMA_NODE?a->numa_node:NUMA_NO_NODE; }
static bool capable(int cap) { assert(cap==CAP_SYS_ADMIN); return admin; }
static int fls_long(unsigned long n) { int out=0;while(n){n>>=1;out++;}return out; }
static int num_possible_cpus(void) { return 2; }
static int bpf_map_precharge_memlock(u32 pages) { assert(pages);precharges++;return fail_charge?-EPERM:0; }
static void *area(size_t size,bool usermap) {
    if(fail_alloc) return NULL;
    assert(size && size<(16*1024*1024));
    void *p=NULL;assert(!posix_memalign(&p,PAGE_SIZE,PAGE_ALIGN(size)));memset(p,0,PAGE_ALIGN(size));
    int i=0;while(i<16&&blocks[i].base)i++;assert(i<16);
    blocks[i].base=p;blocks[i].bytes=PAGE_ALIGN(size);blocks[i].usermap=usermap;allocations++;return p;
}
static void *bpf_map_area_alloc(size_t size,int node) { return area(size,false); }
static void * __vmalloc_node_range(unsigned long size,unsigned long align,unsigned long start,unsigned long end,
        gfp_t flags,pgprot_t prot,unsigned long vm_flags,int node,const void *caller) {
    assert(align==PAGE_SIZE&&start==VMALLOC_START&&end==VMALLOC_END);
    assert(flags==(GFP_USER|__GFP_NOWARN|__GFP_NORETRY|__GFP_ZERO)&&prot==PAGE_KERNEL&&vm_flags==VM_USERMAP);
    return area(size,true);
}
static void release_area(void *base,bool mmap) {
    int i=0;while(i<16&&blocks[i].base!=base)i++;assert(i<16&&blocks[i].usermap==mmap);
    free(base);memset(&blocks[i],0,sizeof(blocks[i]));frees++;
}
static void bpf_map_area_free(void *p) {release_area(p,false);}
static void vfree(void *p) {release_area(p,true);}
static void synchronize_rcu(void) {}
static int remap_vmalloc_range(struct vm_area_struct *vma,void *base,unsigned long pgoff) {
    if(fail_remap) return -EAGAIN;
    int i=0;while(i<16&&blocks[i].base!=base)i++;assert(i<16&&blocks[i].usermap);
    assert(pgoff && pgoff<ULONG_MAX/PAGE_SIZE);
    size_t offset=pgoff*PAGE_SIZE,len=vma->vm_end-vma->vm_start;
    assert(offset>=PAGE_ALIGN(sizeof(struct bpf_map))&&offset<=blocks[i].bytes&&len<=blocks[i].bytes-offset);
    vma->mapped=(unsigned char *)base+offset;vma->vm_flags|=VM_DONTDUMP|VM_DONTEXPAND;return 0;
}
'''
prefix += map_types + '\n' + array_body + '\n'
prefix += r'''
#define ARRAY_CREATE_FLAG_MASK (BPF_F_NUMA_NODE|BPF_F_RDONLY|BPF_F_WRONLY|BPF_F_MMAPABLE)
static int bpf_array_alloc_percpu(struct bpf_array *a) {return fail_percpu;}
static void bpf_array_free_percpu(struct bpf_array *a) {percpu_frees++;}
'''
for name in ['bpf_map_area_mmapable_alloc', 'bpf_map_mmap']:
    prefix += function(sources['kernel/bpf/syscall.c'], name) + '\n'
for name in ['array_map_vmalloc_addr', 'array_map_mmap', 'array_map_alloc', 'array_map_free']:
    prefix += function(sources['kernel/bpf/arraymap.c'], name) + '\n'
main = r'''
static int cases;
static const struct bpf_map_ops ops={.map_mmap=array_map_mmap}, no_mmap={0};
static struct bpf_map *create(u32 entries,u32 value,u32 flags,u32 type) {
    union bpf_attr a={.map_type=type,.key_size=4,.value_size=value,.max_entries=entries,.map_flags=flags};
    struct bpf_map *m=array_map_alloc(&a);if(!IS_ERR(m))m->ops=&ops;return m;
}
static void permission_tests(struct bpf_map *map) {
    for(int mode=0;mode<4;mode++) for(int flags=0;flags<64;flags++) {
        struct file f={.private_data=map,.f_mode=mode,.references=1};
        struct vm_area_struct v={.vm_start=PAGE_SIZE,.vm_end=PAGE_SIZE*2,.vm_flags=flags,.vm_file=&f};
        int expected=0;if(!(flags&VM_SHARED))expected=-EINVAL;
        else if(flags&VM_EXEC)expected=-EACCES;
        else if(!(mode&FMODE_READ)||((flags&VM_WRITE)&&!(mode&FMODE_WRITE)))expected=-EACCES;
        assert(bpf_map_mmap(&f,&v)==expected);
        if(!expected){assert(v.mapped==(unsigned char *)container_of(map,struct bpf_array,map)->value);
            assert(!(v.vm_flags&VM_MAYEXEC));if(!(flags&VM_WRITE))assert(!(v.vm_flags&VM_MAYWRITE));}
        cases++;
    }
    struct file f={.private_data=map,.f_mode=3};
    struct vm_area_struct v={.vm_start=PAGE_SIZE,.vm_end=PAGE_SIZE*2,.vm_flags=VM_SHARED|VM_READ|VM_MAYWRITE|VM_MAYEXEC};
    fail_remap=1;assert(bpf_map_mmap(&f,&v)==-EAGAIN&&!v.mapped);fail_remap=0;cases++;
    const struct bpf_map_ops *old=map->ops;map->ops=&no_mmap;
    assert(bpf_map_mmap(&f,&v)==-EOPNOTSUPP);map->ops=old;cases++;
}
static void mapping_tests(struct bpf_map *map) {
    struct bpf_array *a=container_of(map,struct bpf_array,map);
    u64 bytes=PAGE_ALIGN((u64)map->max_entries*a->elem_size);
    const unsigned long offsets[]={0,1,2,3,7,ULONG_MAX,ULONG_MAX/PAGE_SIZE,ULONG_MAX/PAGE_SIZE+1};
    for(int i=0;i<8;i++)for(int pages=0;pages<=4;pages++) {
        struct vm_area_struct v={.vm_start=PAGE_SIZE,.vm_end=PAGE_SIZE+(unsigned long)pages*PAGE_SIZE,.vm_pgoff=offsets[i]};
        bool good=pages>0&&offsets[i]<=bytes/PAGE_SIZE&&(u64)pages*PAGE_SIZE<=bytes-(u64)offsets[i]*PAGE_SIZE;
        int rc=array_map_mmap(map,&v);assert((rc==0)==good);
        if(good){assert(v.mapped==(unsigned char *)a->value+offsets[i]*PAGE_SIZE);
            assert((uintptr_t)v.mapped%PAGE_SIZE==0);assert(v.vm_flags&(VM_DONTDUMP|VM_DONTEXPAND));}
        cases++;
    }
    struct vm_area_struct v={.vm_start=PAGE_SIZE+1,.vm_end=PAGE_SIZE*2+1};assert(array_map_mmap(map,&v)==-EINVAL);cases++;
    v.vm_start=PAGE_SIZE;v.vm_end=PAGE_SIZE*2-1;assert(array_map_mmap(map,&v)==-EINVAL);cases++;
    v.vm_end=0;assert(array_map_mmap(map,&v)==-EINVAL);cases++;
    u32 old=map->map_type;map->map_type=BPF_MAP_TYPE_PERCPU_ARRAY;v.vm_end=PAGE_SIZE*2;
    assert(array_map_mmap(map,&v)==-EINVAL);map->map_type=old;cases++;
}
static void layout_tests(void) {
    const u32 entries[]={1,2,3,511,512,513,1024};const u32 values[]={1,3,8,15,128};
    for(int privileged=0;privileged<2;privileged++)for(int e=0;e<7;e++)for(int v=0;v<5;v++) {
        admin=privileged;struct bpf_map *map=create(entries[e],values[v],BPF_F_MMAPABLE,BPF_MAP_TYPE_ARRAY);assert(!IS_ERR(map));
        struct bpf_array *a=container_of(map,struct bpf_array,map);void *base=array_map_vmalloc_addr(a);
        assert((uintptr_t)a->value%PAGE_SIZE==0);assert((char *)a->value-(char *)base==PAGE_ALIGN(sizeof(*a)));
        size_t bytes=PAGE_ALIGN((u64)entries[e]*a->elem_size);
        assert(map->pages*PAGE_SIZE>=bytes+PAGE_ALIGN(sizeof(*a)));
        for(size_t b=0;b<bytes;b++)assert((unsigned char)a->value[b]==0);
        a->value[0]=0x5a;struct vm_area_struct area={.vm_start=PAGE_SIZE,.vm_end=PAGE_SIZE*2};
        assert(array_map_mmap(map,&area)==0&&area.mapped[0]==0x5a);area.mapped[0]=0x6a;assert(a->value[0]==0x6a);
        array_map_free(map);cases++;
    }
    admin=true;
}
static void allocation_failure_tests(void) {
    union bpf_attr attr={.map_type=BPF_MAP_TYPE_ARRAY,.key_size=4,.value_size=8,.max_entries=1024,.map_flags=BPF_F_MMAPABLE};
    int before=allocations;fail_charge=1;assert(PTR_ERR(array_map_alloc(&attr))==-EPERM&&allocations==before);fail_charge=0;cases++;
    fail_alloc=1;assert(PTR_ERR(array_map_alloc(&attr))==-ENOMEM&&allocations==before);fail_alloc=0;cases++;
    attr.value_size=1u<<(KMALLOC_SHIFT_MAX-1);assert(PTR_ERR(array_map_alloc(&attr))==-E2BIG);cases++;
    attr.value_size=8;attr.max_entries=UINT32_MAX;assert(PTR_ERR(array_map_alloc(&attr))==-ENOMEM);cases++;
    admin=false;assert(PTR_ERR(array_map_alloc(&attr))==-E2BIG);admin=true;cases++;
    const u32 types[]={BPF_MAP_TYPE_PERCPU_ARRAY,BPF_MAP_TYPE_PROG_ARRAY,BPF_MAP_TYPE_PERF_EVENT_ARRAY,BPF_MAP_TYPE_CGROUP_ARRAY,BPF_MAP_TYPE_ARRAY_OF_MAPS};
    for(int i=0;i<5;i++){attr.map_type=types[i];attr.max_entries=2;assert(PTR_ERR(array_map_alloc(&attr))==-EINVAL);cases++;}
    attr.map_type=BPF_MAP_TYPE_ARRAY;attr.map_flags=BPF_F_MMAPABLE|(1u<<31);assert(PTR_ERR(array_map_alloc(&attr))==-EINVAL);cases++;
    struct bpf_map *regular=create(2,8,0,BPF_MAP_TYPE_ARRAY);assert(!IS_ERR(regular));
    struct vm_area_struct v={.vm_start=PAGE_SIZE,.vm_end=PAGE_SIZE*2};assert(array_map_mmap(regular,&v)==-EINVAL);
    array_map_free(regular);cases++;
    fail_percpu=1;attr.map_type=BPF_MAP_TYPE_PERCPU_ARRAY;attr.map_flags=0;attr.max_entries=2;
    assert(PTR_ERR(array_map_alloc(&attr))==-ENOMEM);fail_percpu=0;cases++;
}
static void put_file(struct file *f) {assert(f->references>0);if(!--f->references)array_map_free(f->private_data);}
static void lifetime_tests(void) {
    struct bpf_map *map=create(1024,8,BPF_F_MMAPABLE,BPF_MAP_TYPE_ARRAY);assert(!IS_ERR(map));
    struct file f={.private_data=map,.f_mode=3,.references=1};
    struct vm_area_struct original={.vm_start=PAGE_SIZE,.vm_end=PAGE_SIZE*2,.vm_flags=VM_SHARED|VM_READ|VM_WRITE,.vm_file=&f};
    assert(bpf_map_mmap(&f,&original)==0);f.references++; // Generic mmap retains vm_file.
    struct vm_area_struct forked=original;f.references++; // Generic fork/split retains vm_file.
    int old=frees;put_file(&f);assert(f.references==2&&frees==old);original.mapped[0]=0x35;
    assert(forked.mapped[0]==0x35);put_file(&f);assert(frees==old);forked.mapped[0]=0x57;
    assert(container_of(map,struct bpf_array,map)->value[0]==0x57);put_file(&f);assert(frees==old+1);cases++;
}
int main(void) {
    assert(BPF_F_MMAPABLE==(1u<<10));allocation_failure_tests();layout_tests();lifetime_tests();
    struct bpf_map *map=create(1024,8,BPF_F_MMAPABLE,BPF_MAP_TYPE_ARRAY);assert(!IS_ERR(map));
    permission_tests(map);mapping_tests(map);array_map_free(map);
    assert(allocations==frees);for(int i=0;i<16;i++)assert(!blocks[i].base);
    printf("{\"cases\":%d,\"allocations_freed\":%d,\"passed\":true}\n",cases,frees);return 0;
}
'''
assert '.map_mmap = array_map_mmap' in sources['kernel/bpf/arraymap.c']
assert '.mmap\t\t= bpf_map_mmap' in sources['kernel/bpf/syscall.c']
assert 'vma->vm_file = get_file(file)' in sources['mm/mmap.c']
assert 'get_file(new->vm_file)' in sources['mm/mmap.c']
assert 'if (!(area->flags & VM_USERMAP))' in sources['mm/vmalloc.c']
results = {}
with tempfile.TemporaryDirectory(prefix='borealis-bpf-mmap-') as temp:
    directory = Path(temp)
    harness = directory / 'mmap-test.c'
    harness.write_text(prefix + main)
    for shift in (12, 14, 16):
        binary = directory / f'mmap-{shift}'
        subprocess.run(['gcc', '-std=gnu11', '-O1', '-g', '-fsanitize=address,undefined',
                        '-fno-omit-frame-pointer', '-no-pie', f'-DPAGE_SHIFT={shift}',
                        str(harness), '-o', str(binary)], check=True)
        results[str(1 << shift)] = json.loads(subprocess.check_output([str(binary)], text=True))
report = {'scope': 'Installed array allocator/mmap C with simulated VM, file lifetime, precharge and per-CPU plumbing',
          'page_size_variants': results, 'cases': sum(r['cases'] for r in results.values()),
          'asan_ubsan': 'passed', 'metadata_not_mapped': True,
          'readonly_write_upgrade_and_exec_rejected': True,
          'source_sha256': {n: hashlib.sha256(value.encode()).hexdigest() for n, value in sources.items()},
          'device_tested': False, 'real_vm_lifetime_tested': False, 'concurrency_tested': False,
          'android17_network_validated': False}
(package / 'validation/bpf-mmap-tests.json').write_text(json.dumps(report, indent=2) + '\n')
print(json.dumps(report, indent=2))
