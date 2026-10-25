/* SPDX-License-Identifier: Apache-2.0
 * Ephemeral feature probe: no pinned maps, cgroup attachment or network writes.
 * Compile against the real AOSP 17 Linux UAPI. All created FDs are closed.
 */
#include <linux/bpf.h>
typedef unsigned long size_t;
static long call(long n,long a,long b,long c,long d,long e,long f) {
 register long x0 __asm__("x0")=a, x1 __asm__("x1")=b, x2 __asm__("x2")=c;
 register long x3 __asm__("x3")=d, x4 __asm__("x4")=e, x5 __asm__("x5")=f;
 register long x8 __asm__("x8")=n;
 __asm__ volatile("svc 0" : "+r"(x0) : "r"(x1),"r"(x2),"r"(x3),"r"(x4),"r"(x5),"r"(x8) : "memory");
 return x0;
}
static size_t length(const char *s){size_t n=0;while(s[n])n++;return n;}
static void say(const char *s){call(64,1,(long)s,length(s),0,0,0);}
static void number(long value) {
 char buffer[32]; int end=31;buffer[end--]='\n';
 unsigned long n=value<0 ? (unsigned long)-value : (unsigned long)value;
 do {buffer[end--]='0'+n%10;n/=10;} while(n);
 if(value<0)buffer[end--]='-';
 call(64,1,(long)&buffer[end+1],31-end,0,0,0);
}
static void clear(union bpf_attr *attr){unsigned char *p=(void*)attr;for(size_t i=0;i<sizeof(*attr);i++)p[i]=0;}
static long bpf(int command,union bpf_attr *attr){return call(280,command,(long)attr,sizeof(*attr),0,0,0);}
void entry(void) {
 union bpf_attr attr;
 clear(&attr);attr.map_type=BPF_MAP_TYPE_ARRAY;attr.key_size=4;attr.value_size=4;attr.max_entries=1;
 long fd=bpf(BPF_MAP_CREATE,&attr);say("array_map_create=");number(fd);
 if(fd>=0) {
  unsigned int key=0,value=0,out=0,cursor=0;
  clear(&attr);attr.map_fd=fd;attr.key=(unsigned long)&key;attr.value=(unsigned long)&value;
  say("array_map_lookup=");number(bpf(BPF_MAP_LOOKUP_ELEM,&attr));
  clear(&attr);attr.batch.map_fd=fd;attr.batch.out_batch=(unsigned long)&cursor;
  attr.batch.keys=(unsigned long)&key;attr.batch.values=(unsigned long)&out;attr.batch.count=1;
  say("map_lookup_batch=");number(bpf(BPF_MAP_LOOKUP_BATCH,&attr));
  call(57,fd,0,0,0,0,0);
 }
 struct bpf_insn insns[2]={{.code=BPF_ALU64|BPF_MOV|BPF_K,.dst_reg=BPF_REG_0,.imm=1},
                            {.code=BPF_JMP|BPF_EXIT}};
 const char license[]="GPL"; char log[1024];
 clear(&attr);attr.prog_type=BPF_PROG_TYPE_CGROUP_SOCKOPT;
 attr.insn_cnt=2;attr.insns=(unsigned long)insns;attr.license=(unsigned long)license;
 attr.log_buf=(unsigned long)log;attr.log_size=sizeof(log);attr.log_level=1;log[0]=0;
 attr.prog_type=BPF_PROG_TYPE_CGROUP_SKB;
 fd=bpf(BPF_PROG_LOAD,&attr);say("baseline_cgroup_skb_program_load=");number(fd);
 if(fd>=0)call(57,fd,0,0,0,0,0);
 attr.prog_type=BPF_PROG_TYPE_CGROUP_SOCKOPT;
 fd=bpf(BPF_PROG_LOAD,&attr);say("cgroup_sockopt_program_load_without_attach_hint=");number(fd);
 if(fd>=0)call(57,fd,0,0,0,0,0);
 attr.expected_attach_type=BPF_CGROUP_GETSOCKOPT;
 fd=bpf(BPF_PROG_LOAD,&attr);say("cgroup_getsockopt_program_load=");number(fd);
 if(fd>=0)call(57,fd,0,0,0,0,0);
 else if(log[0]){log[sizeof(log)-1]=0;say("verifier=");say(log);say("\n");}
 call(93,0,0,0,0,0,0);for(;;);
}
__asm__(".global _start\n_start:\nbl entry\n");
