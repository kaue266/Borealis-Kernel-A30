/* SPDX-License-Identifier: GPL-2.0
 * CGROUP_SOCK context is a live struct sock, never a struct sk_buff.
 * The private argument constraint rejects adjusted context pointers.
 */
static const struct bpf_func_proto bpf_get_socket_cookie_sock_ctx_proto = {
	.func = bpf_get_socket_cookie_sock,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_SOCK_CTX,
};

BPF_CALL_1(bpf_get_socket_uid_sock_ctx, struct sock *, sk)
{
	kuid_t kuid = sock_net_uid(sock_net(sk), sk);

	return from_kuid_munged(sock_net(sk)->user_ns, kuid);
}

static const struct bpf_func_proto bpf_get_socket_uid_sock_ctx_proto = {
	.func = bpf_get_socket_uid_sock_ctx,
	.gpl_only = false,
	.ret_type = RET_INTEGER,
	.arg1_type = ARG_PTR_TO_SOCK_CTX,
};

static const struct bpf_func_proto *
cg_sock_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_get_socket_cookie:
		return &bpf_get_socket_cookie_sock_ctx_proto;
	case BPF_FUNC_get_socket_uid:
		return &bpf_get_socket_uid_sock_ctx_proto;
	default:
		return bpf_base_func_proto(func_id);
	}
}
