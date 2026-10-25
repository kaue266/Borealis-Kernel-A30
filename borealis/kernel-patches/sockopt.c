// SPDX-License-Identifier: GPL-2.0
/*
 * Cgroup socket-option hooks for the R24U backport.
 * Derived from Linux commit 0d01da6afc54 and the Linux v5.10 implementation
 * by Stanislav Fomichev and the Linux BPF contributors.
 * Context validation rejects unsupported socket-pointer access; adding an
 * enum alone must never grant unchecked access to kernel memory.
 */
#include <linux/bpf.h>
#include <linux/bpf-cgroup.h>
#include <linux/cgroup.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <net/sock.h>

static bool sockopt_prog_array_empty(struct cgroup *cgrp,
				    enum bpf_attach_type type)
{
	struct bpf_prog_array *array;
	bool empty;

	rcu_read_lock();
	array = rcu_dereference(cgrp->bpf.effective[type]);
	empty = bpf_prog_array_is_empty(array);
	rcu_read_unlock();
	return empty;
}

static int sockopt_alloc_buf(struct bpf_sockopt_kern *ctx, int length)
{
	if (length < 0)
		return -EINVAL;
	length = min_t(int, length, PAGE_SIZE);
	ctx->optval = kzalloc(max_t(int, length, 1), GFP_USER);
	if (!ctx->optval)
		return -ENOMEM;
	ctx->optval_end = ctx->optval + length;
	return length;
}

int __cgroup_bpf_run_filter_setsockopt(struct sock *sk, int *level,
		int *optname, char __user *optval, int *optlen,
		char **kernel_optval)
{
	struct bpf_sockopt_kern ctx = { .sk = sk, .level = *level,
		.optname = *optname };
	struct cgroup *cgrp;
	int ret, capacity;

	if (!sk || !cgroup_bpf_enabled)
		return 0;
	cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
	if (sockopt_prog_array_empty(cgrp, BPF_CGROUP_SETSOCKOPT))
		return 0;
	if (*optlen < 0)
		return -EINVAL;

	capacity = sockopt_alloc_buf(&ctx, max_t(int, *optlen, 16));
	if (capacity < 0)
		return capacity;
	ctx.optlen = *optlen;
	if (copy_from_user(ctx.optval, optval, min(*optlen, capacity))) {
		ret = -EFAULT;
		goto out;
	}
	lock_sock(sk);
	ret = BPF_PROG_RUN_ARRAY_CHECK(cgrp->bpf.effective[BPF_CGROUP_SETSOCKOPT],
				    &ctx, BPF_PROG_RUN);
	release_sock(sk);
	if (!ret) {
		ret = -EPERM;
		goto out;
	}
	if (ctx.optlen == -1) {
		ret = 1;
		goto out;
	}
	if (ctx.optlen < 0 || ctx.optlen > capacity) {
		ret = -EFAULT;
		goto out;
	}
	*level = ctx.level;
	*optname = ctx.optname;
	/* Zero means continue with the original user buffer, including large
	 * options. Otherwise the caller takes ownership of the bounded buffer.
	 */
	if (ctx.optlen) {
		*optlen = ctx.optlen;
		*kernel_optval = ctx.optval;
		ctx.optval = NULL;
	}
	ret = 0;
out:
	kfree(ctx.optval);
	return ret;
}
EXPORT_SYMBOL(__cgroup_bpf_run_filter_setsockopt);

int __cgroup_bpf_run_filter_getsockopt(struct sock *sk, int level,
		int optname, char __user *optval, int __user *optlen,
		int max_optlen, int retval)
{
	struct bpf_sockopt_kern ctx = { .sk = sk, .level = level,
		.optname = optname, .retval = retval, .optlen = max_optlen };
	struct cgroup *cgrp;
	int ret, capacity;

	if (!sk || !cgroup_bpf_enabled)
		return retval;
	cgrp = sock_cgroup_ptr(&sk->sk_cgrp_data);
	if (sockopt_prog_array_empty(cgrp, BPF_CGROUP_GETSOCKOPT))
		return retval;
	capacity = sockopt_alloc_buf(&ctx, max_optlen);
	if (capacity < 0)
		return capacity;
	if (!retval) {
		if (get_user(ctx.optlen, optlen) || ctx.optlen < 0) {
			ret = -EFAULT;
			goto out;
		}
		if (copy_from_user(ctx.optval, optval, min(ctx.optlen, capacity))) {
			ret = -EFAULT;
			goto out;
		}
	}
	lock_sock(sk);
	ret = BPF_PROG_RUN_ARRAY_CHECK(cgrp->bpf.effective[BPF_CGROUP_GETSOCKOPT],
				    &ctx, BPF_PROG_RUN);
	release_sock(sk);
	if (!ret) {
		ret = -EPERM;
		goto out;
	}
	if (ctx.optlen < 0 || ctx.optlen > capacity ||
	    (ctx.retval && ctx.retval != retval)) {
		ret = -EFAULT;
		goto out;
	}
	if (ctx.optlen && (copy_to_user(optval, ctx.optval, ctx.optlen) ||
			  put_user(ctx.optlen, optlen))) {
		ret = -EFAULT;
		goto out;
	}
	ret = ctx.retval;
out:
	kfree(ctx.optval);
	return ret;
}
EXPORT_SYMBOL(__cgroup_bpf_run_filter_getsockopt);

static const struct bpf_func_proto *
cg_sockopt_func_proto(enum bpf_func_id id, const struct bpf_prog *prog)
{
	switch (id) {
	case BPF_FUNC_map_lookup_elem: return &bpf_map_lookup_elem_proto;
	case BPF_FUNC_map_update_elem: return &bpf_map_update_elem_proto;
	case BPF_FUNC_map_delete_elem: return &bpf_map_delete_elem_proto;
	case BPF_FUNC_get_current_uid_gid: return &bpf_get_current_uid_gid_proto;
	case BPF_FUNC_get_current_pid_tgid: return &bpf_get_current_pid_tgid_proto;
	case BPF_FUNC_get_current_comm: return &bpf_get_current_comm_proto;
	case BPF_FUNC_ktime_get_ns: return &bpf_ktime_get_ns_proto;
	case BPF_FUNC_get_prandom_u32: return &bpf_get_prandom_u32_proto;
	case BPF_FUNC_get_smp_processor_id: return &bpf_get_smp_processor_id_proto;
	case BPF_FUNC_trace_printk:
		return capable(CAP_SYS_ADMIN) ? bpf_get_trace_printk_proto() : NULL;
	default: return NULL;
	}
}

static bool cg_sockopt_is_valid_access(int off, int size,
		enum bpf_access_type type, const struct bpf_prog *prog,
		struct bpf_insn_access_aux *info)
{
	if ((size != 4 && size != 8) || off < 0 ||
	    off > sizeof(struct bpf_sockopt) - size || off % size)
		return false;
	if (type == BPF_WRITE) {
		if (size != 4)
			return false;
		switch (off) {
		case offsetof(struct bpf_sockopt, level):
		case offsetof(struct bpf_sockopt, optname):
			return prog->expected_attach_type == BPF_CGROUP_SETSOCKOPT;
		case offsetof(struct bpf_sockopt, retval):
			return prog->expected_attach_type == BPF_CGROUP_GETSOCKOPT;
		case offsetof(struct bpf_sockopt, optlen): return true;
		default: return false;
		}
	}
	if (type != BPF_READ)
		return false;
	switch (off) {
	case offsetof(struct bpf_sockopt, optval):
		if (size != 8) return false;
		info->reg_type = PTR_TO_PACKET;
		return true;
	case offsetof(struct bpf_sockopt, optval_end):
		if (size != 8) return false;
		info->reg_type = PTR_TO_PACKET_END;
		return true;
	case offsetof(struct bpf_sockopt, level):
	case offsetof(struct bpf_sockopt, optname):
	case offsetof(struct bpf_sockopt, optlen): return size == 4;
	case offsetof(struct bpf_sockopt, retval):
		return size == 4 && prog->expected_attach_type == BPF_CGROUP_GETSOCKOPT;
	default:
		/* PTR_TO_SOCKET and its verifier rules need a separate backport.
		 * Do not expose a kernel pointer as an untyped scalar.
		 */
		return false;
	}
}

#define CG_SOCKOPT_ACCESS_FIELD(T, F) \
	T(BPF_FIELD_SIZEOF(struct bpf_sockopt_kern, F), \
	  si->dst_reg, si->src_reg, offsetof(struct bpf_sockopt_kern, F))

static u32 cg_sockopt_convert_ctx_access(enum bpf_access_type type,
		const struct bpf_insn *si, struct bpf_insn *buffer,
		struct bpf_prog *prog, u32 *target_size)
{
	struct bpf_insn *insn = buffer;

#define CONVERT_FIELD(F) \
	case offsetof(struct bpf_sockopt, F): \
		*target_size = BPF_FIELD_SIZEOF(struct bpf_sockopt_kern, F); \
		if (type == BPF_WRITE) \
			*insn++ = CG_SOCKOPT_ACCESS_FIELD(BPF_STX_MEM, F); \
		else \
			*insn++ = CG_SOCKOPT_ACCESS_FIELD(BPF_LDX_MEM, F); \
		break
	switch (si->off) {
	CONVERT_FIELD(level);
	CONVERT_FIELD(optname);
	CONVERT_FIELD(optlen);
	CONVERT_FIELD(retval);
	CONVERT_FIELD(optval);
	CONVERT_FIELD(optval_end);
	}
#undef CONVERT_FIELD
	return insn - buffer;
}

const struct bpf_verifier_ops cg_sockopt_verifier_ops = {
	.get_func_proto = cg_sockopt_func_proto,
	.is_valid_access = cg_sockopt_is_valid_access,
	.convert_ctx_access = cg_sockopt_convert_ctx_access,
};

const struct bpf_prog_ops cg_sockopt_prog_ops = {};
