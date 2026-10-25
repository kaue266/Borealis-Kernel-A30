/* Fixed syscall-only RAM job: no attachments, pinning, or packets transmitted. */
#include "bpf_probe_runtime.h"
static char logbuf[32768];static int cases;
struct local_addr {unsigned short family,port;unsigned int address;unsigned char pad[8];};
static struct bpf_insn ins(int c,int d,int s,int o,int i){return (struct bpf_insn){.code=c,.dst_reg=d,.src_reg=s,.off=o,.imm=i};}
static void fail(const char *step){printf("{\"passed\":false,\"step\":\"%s\",\"errno\":%d,\"cases\":%d}\n",step,errno,cases);size_t n=0;while(n<sizeof(logbuf)&&logbuf[n])n++;size_t start=n>1024?n-1024:0;probe_call(__NR_write,1,(long)(logbuf+start),n-start,0,0,0);exit(0);}
static int load(struct bpf_insn *p,int n){union bpf_attr a={0};memset(logbuf,0,sizeof(logbuf));a.prog_type=BPF_PROG_TYPE_CGROUP_SKB;a.insns=(uintptr_t)p;a.insn_cnt=n;a.license=(uintptr_t)"GPL";a.log_buf=(uintptr_t)logbuf;a.log_size=sizeof(logbuf);a.log_level=1;return syscall(__NR_bpf,BPF_PROG_LOAD,&a,sizeof(a));}
static int run(int fd,int size){char packet[65]={0},out[65];union bpf_attr a={0};a.test.prog_fd=fd;a.test.data_size_in=size;a.test.data_size_out=65;a.test.data_in=(uintptr_t)packet;a.test.data_out=(uintptr_t)out;a.test.repeat=1;if(syscall(__NR_bpf,BPF_PROG_TEST_RUN,&a,sizeof(a)))fail("test_run");return a.test.retval;}
static int program(struct bpf_insn *p,int helper,int variant,int port){
 int n=0,null=-1;
 p[n++]=ins(0x62,10,0,-16,0);p[n++]=ins(0x62,10,0,-12,0x0100007f);
 p[n++]=ins(0x6a,10,0,-8,0x1234);p[n++]=ins(0x6a,10,0,-6,port);
 p[n++]=ins(0xbf,2,10,0,0);p[n++]=ins(0x07,2,0,0,-16);p[n++]=ins(0xb7,3,0,0,12);p[n++]=ins(0xb7,4,0,0,-1);p[n++]=ins(0xb7,5,0,0,0);p[n++]=ins(0x85,0,0,0,helper);p[n++]=ins(0xbf,6,0,0,0);
 if(variant!=2){null=n;p[n++]=ins(0x15,6,0,0,0);}
 if(variant==1){/* Leak on non-NULL path. */}
 else{
  if(variant==3)p[n++]=ins(0x07,6,0,0,1);
  p[n++]=ins(0x61,7,6,4,0);
  p[n++]=ins(0x7b,10,6,-24,0);
  p[n++]=ins(0xbf,1,6,0,0);p[n++]=ins(0x85,0,0,0,BPF_FUNC_sk_release);
  if(variant==4){p[n++]=ins(0xbf,1,6,0,0);p[n++]=ins(0x85,0,0,0,BPF_FUNC_sk_release);}
  if(variant==5)p[n++]=ins(0x61,7,6,4,0);
  if(variant==6){p[n++]=ins(0x79,6,10,-24,0);p[n++]=ins(0x61,7,6,4,0);}
 }
 p[n++]=ins(0xb7,0,0,0,1);p[n++]=ins(0x95,0,0,0,0);
 int none=n;p[n++]=ins(0xb7,0,0,0,0);p[n++]=ins(0x95,0,0,0,0);if(null>=0)p[null].off=none-null-1;
 return n;
}
int main(void){
 struct bpf_insn p[64];
 for(int protocol=0;protocol<2;protocol++){
  int sock=probe_call(__NR_socket,2,protocol?1:2,0,0,0,0);if(sock<0)fail("create_local_socket");
  struct local_addr addr={.family=2,.address=0x0100007f};unsigned int len=sizeof(addr);
  if(probe_call(__NR_bind,sock,(long)&addr,sizeof(addr),0,0,0))fail("bind_loopback_no_traffic");
  if(protocol&&probe_call(__NR_listen,sock,1,0,0,0,0))fail("listen_local_socket");
  if(probe_call(__NR_getsockname,sock,(long)&addr,(long)&len,0,0,0)||!addr.port)fail("read_ephemeral_local_port");
  int helper=protocol?BPF_FUNC_sk_lookup_tcp:BPF_FUNC_sk_lookup_udp;
  for(int variant=0;variant<=6;variant++){
   int fd=load(p,program(p,helper,variant,addr.port));
   if(!variant){if(fd<0)fail("load_owned_socket_lookup_release");cases++;for(int repeat=0;repeat<32;repeat++){if(run(fd,64)!=1)fail("actual_loopback_lookup_and_release");cases++;}close(fd);}
   else {if(fd>=0){close(fd);fail("unsafe_socket_owner_program_accepted");}cases++;}
  }
  close(sock);
 }
 /* Borrowed skb->sk must never be released as a lookup-owned socket. */
 p[0]=ins(0x79,1,1,168,0);p[1]=ins(0x15,1,0,1,0);p[2]=ins(0x85,0,0,0,BPF_FUNC_sk_release);p[3]=ins(0xb7,0,0,0,1);p[4]=ins(0x95,0,0,0,0);
 int fd=load(p,5);if(fd>=0){close(fd);fail("borrowed_socket_release_accepted");}cases++;
 /* The compiler's exact boolean sign-extension sequence must retain bounds. */
 p[0]=ins(0x61,0,1,0,0);p[1]=ins(0x57,0,0,0,1);p[2]=ins(0x67,0,0,0,32);p[3]=ins(0xc7,0,0,0,32);p[4]=ins(0x95,0,0,0,0);
 fd=load(p,5);if(fd<0)fail("valid_boolean_arsh_rejected");cases++;if(run(fd,64)!=0||run(fd,65)!=1)fail("execute_boolean_arsh");cases++;close(fd);
 p[1].imm=3;fd=load(p,5);if(fd>=0){close(fd);fail("out_of_range_arsh_return_accepted");}cases++;
 printf("{\"passed\":true,\"cases\":%d,\"attached_or_pinned\":false,\"packets_transmitted\":false,\"android_boot_validated\":false}\n",cases);return 0;
}
