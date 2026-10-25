/* Borrowed socket pointers are never adjusted or reconstructed from scalars. */
static bool bpf_sock_reg_is_unmodified(const struct bpf_reg_state *reg)
{
	return reg->type == PTR_TO_SOCKET && !reg->off &&
		tnum_is_const(reg->var_off) && !reg->var_off.value &&
		!reg->smin_value && !reg->smax_value &&
		!reg->umin_value && !reg->umax_value;
}

static int check_sock_access(struct bpf_verifier_env *env, int insn_idx,
			     u32 regno, int off, int size,
			     enum bpf_access_type type)
{
	struct bpf_reg_state *reg = &env->cur_state.regs[regno];
	struct bpf_insn_access_aux info = {};

	if (!bpf_sock_reg_is_unmodified(reg) ||
	    !bpf_sock_is_valid_access(off, size, type, &info)) {
		verbose("R%d invalid socket access off=%d size=%d\n", regno, off, size);
		return -EACCES;
	}
	env->insn_aux_data[insn_idx].ctx_field_size = info.ctx_field_size;
	return 0;
}

static bool bpf_ptr_needs_conversion(enum bpf_reg_type type)
{
	return type == PTR_TO_CTX || type == PTR_TO_SOCKET;
}
