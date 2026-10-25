/* SPDX-License-Identifier: GPL-2.0
 * Borrowed socket metadata access, adapted to R24U from Linux v5.10.
 * Only hooks whose context holds a live, non-NULL socket may supply this
 * register type. Acquired/nullable sockets still require a separate port.
 */
bool bpf_sock_is_valid_access(int off, int size, enum bpf_access_type type,
			    struct bpf_insn_access_aux *info)
{
	int field;

	if (type != BPF_READ || (size != 1 && size != 2 && size != 4) ||
	    off < 0 || off > sizeof(struct bpf_sock) - size || off % size)
		return false;
	field = off & ~3;
	if ((off & 3) + size > 4)
		return false;
	switch (field) {
	case offsetof(struct bpf_sock, bound_dev_if):
	case offsetof(struct bpf_sock, mark):
	case offsetof(struct bpf_sock, priority):
		if (size != 4)
			return false;
		break;
	case offsetof(struct bpf_sock, family):
	case offsetof(struct bpf_sock, type):
	case offsetof(struct bpf_sock, protocol):
	case offsetof(struct bpf_sock, src_ip4):
	case offsetof(struct bpf_sock, src_ip6[0]) ... offsetof(struct bpf_sock, src_ip6[3]):
	case offsetof(struct bpf_sock, src_port):
	case offsetof(struct bpf_sock, dst_port):
	case offsetof(struct bpf_sock, dst_ip4):
	case offsetof(struct bpf_sock, dst_ip6[0]) ... offsetof(struct bpf_sock, dst_ip6[3]):
	case offsetof(struct bpf_sock, state):
	case offsetof(struct bpf_sock, rx_queue_mapping):
		break;
	default:
		return false;
	}
	info->ctx_field_size = 4;
	return true;
}
