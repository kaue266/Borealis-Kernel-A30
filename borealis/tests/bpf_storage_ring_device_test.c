/* SPDX-License-Identifier: GPL-2.0-only
 * Fixed ephemeral BPF/BTF probe. No file/partition writes, pinning, external
 * network traffic, cgroup attachment, reboot or SELinux changes.
 * Negative programs are loaded only and never executed.
 */
#include "bpf_probe_runtime.h"
void *memcpy(void *dst,const void *src,size_t n){volatile unsigned char *d=dst;const volatile unsigned char *s=src;for(size_t i=0;i<n;i++)d[i]=s[i];return dst;}
static int cases;
static char verifier_log[32768];
static void fail(const char *step)
{
 printf("{\"passed\":false,\"step\":\"%s\",\"errno\":%d,\"cases\":%d}\n%s\n",step,errno,cases,verifier_log);
 /* The live transport suppresses failed-process output. Return the JSON
  * failure explicitly; callers must inspect passed, never infer from status. */
 exit(0);
}
static int bpf(int command,union bpf_attr *a){return syscall(__NR_bpf,command,a,sizeof(*a));}
static struct bpf_insn ins(unsigned char c,int d,int s,int o,int i)
{return (struct bpf_insn){.code=c,.dst_reg=d,.src_reg=s,.off=o,.imm=i};}
static int load(struct bpf_insn *p,int count)
{
 union bpf_attr a={0};memset(verifier_log,0,sizeof(verifier_log));
 /* CGROUP_SKB uses the existing isolated TEST_RUN handler; no attachment. */
 a.prog_type=BPF_PROG_TYPE_CGROUP_SKB;a.insn_cnt=count;a.insns=(uintptr_t)p;
 a.license=(uintptr_t)"GPL";a.log_buf=(uintptr_t)verifier_log;a.log_size=sizeof(verifier_log);a.log_level=1;
 return bpf(BPF_PROG_LOAD,&a);
}
static int map(int type,int key,int value,int entries,int flags,int btf_fd)
{
 union bpf_attr a={0};a.map_type=type;a.key_size=key;a.value_size=value;a.max_entries=entries;a.map_flags=flags;
 if(btf_fd>=0){a.btf_fd=btf_fd;a.btf_key_type_id=1;a.btf_value_type_id=1;}
 return bpf(BPF_MAP_CREATE,&a);
}
static int elem(int command,int fd,int key,uint32_t *value,int flags)
{
 union bpf_attr a={0};a.map_fd=fd;a.key=(uintptr_t)&key;
 if(command!=BPF_MAP_DELETE_ELEM){a.value=(uintptr_t)value;a.flags=flags;}
 return bpf(command,&a);
}
static void sk_storage(void)
{
 struct {unsigned short magic;unsigned char version,flags;uint32_t hdr_len,type_off,type_len,str_off,str_len;uint32_t name,info,size,encoding;char strings[5];} __attribute__((packed)) bt={
  .magic=0xeb9f,.version=1,.hdr_len=24,.type_len=16,.str_off=16,.str_len=5,.name=1,.info=1u<<24,.size=4,.encoding=(1u<<24)|32,.strings="\0int"};
 union bpf_attr a={0};a.btf=(uintptr_t)&bt;a.btf_size=sizeof(bt);a.btf_log_buf=(uintptr_t)verifier_log;a.btf_log_size=sizeof(verifier_log);a.btf_log_level=1;
 int btf_fd=bpf(BPF_BTF_LOAD,&a);if(btf_fd<0)fail("load_actual_btf_int_type");cases++;
 int fd=map(BPF_MAP_TYPE_SK_STORAGE,4,4,0,BPF_F_NO_PREALLOC,btf_fd);
 if(fd<0)fail("create_btf_socket_storage");cases++;
 close(btf_fd);/* Map must retain the BTF descriptor after its user fd closes. */
 int sock=probe_call(__NR_socket,2,2,0,0,0,0);if(sock<0)fail("create_unconnected_test_udp_socket");
 uint32_t value=0x13579;
 if(elem(BPF_MAP_UPDATE_ELEM,fd,sock,&value,BPF_NOEXIST))fail("set_socket_storage");cases++;
 value=0;if(elem(BPF_MAP_LOOKUP_ELEM,fd,sock,&value,0)||value!=0x13579)fail("lookup_socket_storage");cases++;
 if(elem(BPF_MAP_DELETE_ELEM,fd,sock,&value,0))fail("delete_socket_storage");cases++;
 if(elem(BPF_MAP_LOOKUP_ELEM,fd,sock,&value,0)==0)fail("reject_deleted_socket_storage");cases++;
 value=0x2468;if(elem(BPF_MAP_UPDATE_ELEM,fd,sock,&value,BPF_NOEXIST))fail("recreate_socket_storage");cases++;
 close(sock);if(elem(BPF_MAP_LOOKUP_ELEM,fd,sock,&value,0)==0)fail("reject_closed_socket_descriptor");cases++;
 close(fd);
 int invalid=map(BPF_MAP_TYPE_SK_STORAGE,4,4,0,BPF_F_NO_PREALLOC,-1);
 if(invalid>=0){close(invalid);fail("reject_storage_without_btf");}cases++;
 printf("socket_storage_btf_descriptor_and_socket_lifetime_pass\n");
}
static int reserve_program(struct bpf_insn *p,int fd,int variant)
{
 int n=0;
 p[n++]=ins(0x18,1,BPF_PSEUDO_MAP_FD,0,fd);p[n++]=ins(0,0,0,0,0);
 p[n++]=ins(0xb7,2,0,0,16);p[n++]=ins(0xb7,3,0,0,0);
 p[n++]=ins(0x85,0,0,0,BPF_FUNC_ringbuf_reserve);
 int branch=n;
 if(variant!=1)p[n++]=ins(0x15,0,0,0,0);/* NULL check unless intentional negative. */
 p[n++]=ins(0xbf,6,0,0,0);
 p[n++]=ins(0x7a,6,0,variant==2?16:0,0x1234);
 if(variant!=4){
  p[n++]=ins(0xbf,1,6,0,0);p[n++]=ins(0xb7,2,0,0,0);
  p[n++]=ins(0x85,0,0,0,BPF_FUNC_ringbuf_submit);
 }
 if(variant==3)p[n++]=ins(0x7a,6,0,0,0x5678);/* Released alias. */
 if(variant==5){
  p[n++]=ins(0xbf,1,6,0,0);p[n++]=ins(0xb7,2,0,0,0);
  p[n++]=ins(0x85,0,0,0,BPF_FUNC_ringbuf_discard);/* Double release. */
 }
 if(variant!=1)p[branch].off=n-branch-1;
 p[n++]=ins(0xb7,0,0,0,1);p[n++]=ins(0x95,0,0,0,0);return n;
}
static void ring(void)
{
 long page=sysconf(_SC_PAGESIZE);if(page!=4096)fail("expected_a30_page_size");
 int fd=map(BPF_MAP_TYPE_RINGBUF,0,0,page,0,-1);if(fd<0)fail("create_ring_buffer");cases++;
 void *bad=mmap(NULL,2*page,PROT_READ|PROT_WRITE,MAP_SHARED,fd,page);
 if(bad!=MAP_FAILED){munmap(bad,2*page);fail("reject_write_to_producer_or_data");}cases++;
 volatile uint64_t *consumer=mmap(NULL,page,PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
 volatile uint64_t *producer=mmap(NULL,3*page,PROT_READ,MAP_SHARED,fd,page);
 if(consumer==MAP_FAILED||producer==MAP_FAILED)fail("map_ring_consumer_and_producer");cases++;
 if(mprotect((void *)producer,3*page,PROT_READ|PROT_WRITE)==0)fail("reject_upgrade_producer_mapping");cases++;
 struct bpf_insn p[32];int count=reserve_program(p,fd,0),prog=load(p,count);
 if(prog<0)fail("load_checked_reserve_submit_program");cases++;
 char packet[64]={0},out[64]={0};union bpf_attr a={0};a.test.prog_fd=prog;a.test.data_size_in=sizeof(packet);a.test.data_size_out=sizeof(out);a.test.data_in=(uintptr_t)packet;a.test.data_out=(uintptr_t)out;a.test.repeat=1;
 if(bpf(BPF_PROG_TEST_RUN,&a)||a.test.retval!=1)fail("execute_checked_reserve_submit");cases++;
 if(*consumer!=0||*producer!=24)fail("ring_record_positions");
 volatile uint32_t *header=(volatile uint32_t *)((volatile char *)producer+page);
 volatile uint64_t *data=(volatile uint64_t *)(header+2);
 if(header[0]!=16||data[0]!=0x1234)fail("committed_ring_record_payload");cases++;
 *consumer=*producer;close(prog);
 for(int variant=1;variant<=5;variant++){
  count=reserve_program(p,fd,variant);int rejected=load(p,count);
  if(rejected>=0){close(rejected);fail("verifier_accepted_unsafe_reservation_program");}cases++;
 }
 /* fd closure must preserve both existing mappings until munmap. */
 close(fd);if(*producer!=24||*consumer!=24||data[0]!=0x1234)fail("ring_mapping_lifetime_after_fd_close");cases++;
 munmap((void *)consumer,page);munmap((void *)producer,3*page);
 printf("ring_reserve_submit_payload_mmap_and_negative_verifier_pass\n");
}
int main(void)
{
 sk_storage();ring();printf("{\"passed\":true,\"cases\":%d,\"android_boot_validated\":false}\n",cases);return 0;
}
