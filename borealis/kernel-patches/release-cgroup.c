/* Release is a notification: every effective program runs, and its return
 * value cannot deny closing the socket. The caller still owns the live sock.
 * R24U's array runner holds RCU across the complete program sequence.
 */
void __cgroup_bpf_run_sock_release(struct sock *sk)
{
	struct cgroup *cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);

	(void)BPF_PROG_RUN_ARRAY_CHECK(
		cgrp->bpf.effective[BPF_CGROUP_INET_SOCK_RELEASE], sk, BPF_PROG_RUN);
}
EXPORT_SYMBOL(__cgroup_bpf_run_sock_release);
