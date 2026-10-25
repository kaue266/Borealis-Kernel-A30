/* SPDX-License-Identifier: GPL-2.0
 * Array batch lookup adapted from Linux commit cb4d03ab499d.
 * Keys and values have separate allocations: this includes the fix for the
 * mixed-stride buffer corruption described in Linux commit 953824e508b2.
 */
int bpf_array_lookup_batch(struct bpf_map *map, const union bpf_attr *attr,
			  union bpf_attr __user *uattr)
{
	void __user *ukeys = u64_to_user_ptr(attr->batch.keys);
	void __user *uvalues = u64_to_user_ptr(attr->batch.values);
	void __user *in = u64_to_user_ptr(attr->batch.in_batch);
	void *value = NULL, *ptr;
	u32 key = 0, last = 0, count = 0, limit = attr->batch.count;
	size_t stride = round_up((size_t)map->value_size, 8), value_size;
	bool percpu = map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY;
	int ret = 0;

	if (attr->batch.flags || attr->batch.elem_flags)
		return -EINVAL;
	if (!limit)
		return 0;
	if (put_user(0, &uattr->batch.count))
		return -EFAULT;
	if (percpu && stride > SIZE_MAX / num_possible_cpus())
		return -E2BIG;
	value_size = percpu ? stride * num_possible_cpus() : map->value_size;
	if (!value_size || limit > SIZE_MAX / value_size ||
	    limit > SIZE_MAX / sizeof(key))
		return -E2BIG;
	if (in) {
		if (copy_from_user(&key, in, sizeof(key)))
			return -EFAULT;
		/* Array get_next_key restarts for a non-existent key. */
		key = key >= map->max_entries ? 0 : key + 1;
	}
	value = kmalloc(value_size, GFP_USER | __GFP_NOWARN);
	if (!value)
		return -ENOMEM;
	while (count < limit) {
		if (key >= map->max_entries) {
			ret = -ENOENT;
			break;
		}
		if (percpu) {
			ret = bpf_percpu_array_copy(map, &key, value);
		} else {
			rcu_read_lock();
			ptr = map->ops->map_lookup_elem(map, &key);
			if (ptr)
				memcpy(value, ptr, value_size);
			rcu_read_unlock();
			ret = ptr ? 0 : -ENOENT;
		}
		if (ret)
			break;
		if (copy_to_user(ukeys + (size_t)count * sizeof(key), &key, sizeof(key)) ||
		    copy_to_user(uvalues + (size_t)count * value_size, value, value_size)) {
			ret = -EFAULT;
			break;
		}
		last = key++;
		count++;
	}
	if (ret != -EFAULT &&
	    (put_user(count, &uattr->batch.count) ||
	     (count && copy_to_user(u64_to_user_ptr(attr->batch.out_batch), &last, sizeof(last)))))
		ret = -EFAULT;
	kfree(value);
	return ret;
}
