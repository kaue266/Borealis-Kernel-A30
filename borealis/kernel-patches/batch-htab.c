/* SPDX-License-Identifier: GPL-2.0
 * Bounded hash-map batch lookup for R24U, derived from Linux commit
 * 057996380a42 (Brian Vazquez and the Linux BPF contributors).
 * LRU frees follow the R24U lock ordering: release the bucket lock first.
 * Map-value BPF spin locks are not implemented here; nonzero flags fail.
 */
static int htab_map_batch(struct bpf_map *map, const union bpf_attr *attr,
			  union bpf_attr __user *uattr, bool do_delete)
{
	struct bpf_htab *htab = container_of(map, struct bpf_htab, map);
	void __user *ukeys = u64_to_user_ptr(attr->batch.keys);
	void __user *uvalues = u64_to_user_ptr(attr->batch.values);
	void __user *ubatch = u64_to_user_ptr(attr->batch.in_batch);
	void *keys = NULL, *values = NULL;
	struct htab_elem **deleted = NULL, *element;
	struct hlist_nulls_node *node, *next;
	size_t value_size, cpu_stride;
	u32 bucket = 0, total = 0, capacity = 5, entries, freed, i;
	u32 max_count = attr->batch.count, key_size = map->key_size;
	bool percpu = htab_is_percpu(htab), lru = htab_is_lru(htab);
	unsigned long irq_flags;
	int ret = 0;

	if (attr->batch.flags || attr->batch.elem_flags)
		return -EINVAL;
	if (!max_count)
		return 0;
	if (put_user(0, &uattr->batch.count))
		return -EFAULT;
	if (ubatch && copy_from_user(&bucket, ubatch, sizeof(bucket)))
		return -EFAULT;
	if (bucket >= htab->n_buckets)
		return -ENOENT;
	cpu_stride = round_up((size_t)map->value_size, 8);
	if (percpu && cpu_stride > SIZE_MAX / num_possible_cpus())
		return -E2BIG;
	value_size = percpu ? cpu_stride * num_possible_cpus() : map->value_size;
	if (!key_size || !value_size || max_count > SIZE_MAX / key_size ||
	    max_count > SIZE_MAX / value_size)
		return -E2BIG;

allocate:
	keys = kmalloc_array(capacity, key_size, GFP_USER | __GFP_NOWARN);
	values = kmalloc_array(capacity, value_size, GFP_USER | __GFP_NOWARN);
	if (do_delete && lru)
		deleted = kmalloc_array(capacity, sizeof(*deleted), GFP_USER | __GFP_NOWARN);
	if (!keys || !values || (do_delete && lru && !deleted)) {
		ret = -ENOMEM;
		goto finish;
	}
again:
	preempt_disable();
	this_cpu_inc(bpf_prog_active);
	rcu_read_lock();
	raw_spin_lock_irqsave(&htab->buckets[bucket].lock, irq_flags);
	entries = 0;
	hlist_nulls_for_each_entry_rcu(element, node,
			&htab->buckets[bucket].head, hash_node)
		entries++;
	if (entries > max_count - total) {
		ret = total ? 0 : -ENOSPC;
		goto unlock_finish;
	}
	if (entries > capacity) {
		capacity = entries;
		raw_spin_unlock_irqrestore(&htab->buckets[bucket].lock, irq_flags);
		rcu_read_unlock();
		this_cpu_dec(bpf_prog_active);
		preempt_enable();
		kfree(keys);
		kfree(values);
		kfree(deleted);
		deleted = NULL;
		goto allocate;
	}
	i = 0;
	freed = 0;
	/* Save the next node before free_htab_elem reuses the element storage. */
	node = rcu_dereference_raw(htab->buckets[bucket].head.first);
	while (!is_a_nulls(node)) {
		element = hlist_nulls_entry(node, struct htab_elem, hash_node);
		next = rcu_dereference_raw(node->next);
		memcpy(keys + (size_t)i * key_size, element->key, key_size);
		if (percpu) {
			void __percpu *ptr = htab_elem_get_ptr(element, key_size);
			size_t offset = 0;
			int cpu;
			for_each_possible_cpu(cpu) {
				bpf_long_memcpy(values + (size_t)i * value_size + offset,
						per_cpu_ptr(ptr, cpu), cpu_stride);
				offset += cpu_stride;
			}
		} else {
			memcpy(values + (size_t)i * value_size,
			       element->key + round_up(key_size, 8), value_size);
		}
		if (do_delete) {
			hlist_nulls_del_rcu(&element->hash_node);
			if (lru)
				deleted[freed++] = element;
			else
				free_htab_elem(htab, element);
		}
		i++;
		node = next;
	}
	raw_spin_unlock_irqrestore(&htab->buckets[bucket].lock, irq_flags);
	for (i = 0; i < freed; i++)
		bpf_lru_push_free(&htab->lru, &deleted[i]->lru_node);
	rcu_read_unlock();
	this_cpu_dec(bpf_prog_active);
	preempt_enable();
	if (entries && (copy_to_user(ukeys + (size_t)total * key_size, keys,
				    (size_t)entries * key_size) ||
			copy_to_user(uvalues + (size_t)total * value_size, values,
				     (size_t)entries * value_size))) {
		ret = -EFAULT;
		goto finish;
	}
	total += entries;
	bucket++;
	if (bucket >= htab->n_buckets) {
		ret = -ENOENT;
		goto finish;
	}
	if (total < max_count)
		goto again;
	goto finish;

unlock_finish:
	raw_spin_unlock_irqrestore(&htab->buckets[bucket].lock, irq_flags);
	rcu_read_unlock();
	this_cpu_dec(bpf_prog_active);
	preempt_enable();
finish:
	/* EFAULT can occur after deletions: count is not a trustworthy result. */
	if (ret != -EFAULT &&
	    (copy_to_user(u64_to_user_ptr(attr->batch.out_batch), &bucket, sizeof(bucket)) ||
	     put_user(total, &uattr->batch.count)))
		ret = -EFAULT;
	kfree(keys);
	kfree(values);
	kfree(deleted);
	return ret;
}

static int htab_map_lookup_batch(struct bpf_map *map, const union bpf_attr *attr,
				 union bpf_attr __user *uattr)
{
	return htab_map_batch(map, attr, uattr, false);
}

static int htab_map_lookup_and_delete_batch(struct bpf_map *map,
		const union bpf_attr *attr, union bpf_attr __user *uattr)
{
	return htab_map_batch(map, attr, uattr, true);
}
