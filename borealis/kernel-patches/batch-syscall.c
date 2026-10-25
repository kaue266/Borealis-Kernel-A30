/* The outer bpf syscall retains security_bpf and unprivileged-BPF checks. */
#define BPF_MAP_BATCH_LAST_FIELD batch.flags

static int bpf_map_do_batch(const union bpf_attr *attr,
			  union bpf_attr __user *uattr, int command)
{
	struct fd file;
	struct bpf_map *map;
	int ret;

	if (CHECK_ATTR(BPF_MAP_BATCH))
		return -EINVAL;
	if (attr->batch.flags || attr->batch.elem_flags)
		return -EINVAL;
	file = fdget(attr->batch.map_fd);
	map = __bpf_map_get(file);
	/* In R24U __bpf_map_get releases a non-map descriptor on error. */
	if (IS_ERR(map))
		return PTR_ERR(map);
	if (!(file.file->f_mode & FMODE_CAN_READ) ||
	    (command == BPF_MAP_LOOKUP_AND_DELETE_BATCH &&
	     !(file.file->f_mode & FMODE_CAN_WRITE))) {
		ret = -EPERM;
		goto out;
	}
	if (command == BPF_MAP_LOOKUP_BATCH)
		ret = map->ops->map_lookup_batch ?
			map->ops->map_lookup_batch(map, attr, uattr) : -ENOTSUPP;
	else
		ret = map->ops->map_lookup_and_delete_batch ?
			map->ops->map_lookup_and_delete_batch(map, attr, uattr) : -ENOTSUPP;
out:
	fdput(file);
	return ret;
}
