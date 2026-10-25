/* Fixed RAM probe: isolated BPF LOAD/TEST_RUN, no attachment or pinning. */
#include "bpf_probe_runtime.h"
void *memcpy(void *dst,const void *src,size_t n){volatile unsigned char *d=dst;const volatile unsigned char *s=src;for(size_t i=0;i<n;i++)d[i]=s[i];return dst;}
static char logbuf[32768];static int cases;
static struct bpf_insn ins(int c,int d,int s,int o,int i){return (struct bpf_insn){.code=c,.dst_reg=d,.src_reg=s,.off=o,.imm=i};}
static void fail(const char *step){printf("{\"passed\":false,\"step\":\"%s\",\"errno\":%d,\"cases\":%d}\n%s\n",step,errno,cases,logbuf);exit(0);}
static int load(struct bpf_insn *p,int count,int type,int attach){
 union bpf_attr a={0};memset(logbuf,0,sizeof(logbuf));a.prog_type=type;a.expected_attach_type=attach;
 a.insn_cnt=count;a.insns=(uintptr_t)p;a.license=(uintptr_t)"GPL";
 a.log_buf=(uintptr_t)logbuf;a.log_size=sizeof(logbuf);a.log_level=1;
 return syscall(__NR_bpf,BPF_PROG_LOAD,&a,sizeof(a));
}
static int program(struct bpf_insn *p,int variant){
 int n=0;int common=-1,full=-1;
 p[n++]=ins(0x79,1,1,168,0);/* ctx->sk: nullable sock_common. */
 if(variant!=1){common=n;p[n++]=ins(0x15,1,0,0,0);}
 if(variant==2)p[n++]=ins(0x07,1,0,0,1);/* Adjusted socket pointer must reject. */
 if(variant==3){p[n++]=ins(0x61,2,1,8,0);}/* Common pointer cannot read full type. */
 else if(variant==5){p[n++]=ins(0x61,2,1,4,0);}/* Common family is safe after NULL check. */
 else{
  p[n++]=ins(0x85,0,0,0,BPF_FUNC_sk_fullsock);
  p[n++]=ins(0xbf,6,0,0,0);
  if(variant!=4){full=n;p[n++]=ins(0x15,6,0,0,0);}
  p[n++]=ins(0x61,2,6,4,0);
 }
 int end=n;p[n++]=ins(0xb7,0,0,0,1);p[n++]=ins(0x95,0,0,0,0);
 if(common>=0)p[common].off=end-common-1;
 if(full>=0)p[full].off=end-full-1;
 return n;
}
int main(void){
 struct bpf_insn p[20];
 for(int variant=0;variant<=5;variant++){
  int n=program(p,variant),fd=load(p,n,BPF_PROG_TYPE_CGROUP_SKB,0);
  if(variant==0||variant==5){
   if(fd<0)fail("load_checked_borrowed_socket_context");cases++;
   if(variant==0){char packet[64]={0},out[64];union bpf_attr a={0};a.test.prog_fd=fd;a.test.data_size_in=64;a.test.data_size_out=64;a.test.data_in=(uintptr_t)packet;a.test.data_out=(uintptr_t)out;a.test.repeat=1;
    if(syscall(__NR_bpf,BPF_PROG_TEST_RUN,&a,sizeof(a))||a.test.retval!=1)fail("execute_null_socket_path");cases++;
   }close(fd);
  }else{if(fd>=0){close(fd);fail("unsafe_socket_context_program_accepted");}cases++;}
 }
 p[0]=ins(0xb7,0,0,0,1);p[1]=ins(0x95,0,0,0,0);
 int fd=load(p,2,BPF_PROG_TYPE_CGROUP_SOCK,34);
 if(fd<0)fail("standard_socket_release_abi_34");close(fd);cases++;
 fd=load(p,2,BPF_PROG_TYPE_CGROUP_SOCK,23);
 if(fd>=0){close(fd);fail("reject_old_private_release_slot_23");}cases++;
 printf("{\"passed\":true,\"cases\":%d,\"attached_or_pinned\":false,\"android_boot_validated\":false}\n",cases);
 return 0;
}
