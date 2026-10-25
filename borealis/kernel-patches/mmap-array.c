/* SPDX-License-Identifier: GPL-2.0-only
 * Array mmap layout adapted from Linux v5.10 to the R24U allocator.
 * Metadata stays in preceding pages and must never be mapped to userspace.
 */
static void *array_map_vmalloc_addr(struct bpf_array *array)
{
	return (char *)array - PAGE_ALIGN(sizeof(*array)) +
		offsetof(struct bpf_array, value);
}

static int array_map_mmap(struct bpf_map *map, struct vm_area_struct *vma)
{
	struct bpf_array *array = container_of(map, struct bpf_array, map);
	u64 value_bytes = PAGE_ALIGN((u64)map->max_entries * array->elem_size);
	u64 offset;
	unsigned long length;
	pgoff_t header_pages = PAGE_ALIGN(sizeof(*array)) >> PAGE_SHIFT;

	if (map->map_type != BPF_MAP_TYPE_ARRAY ||
	    !(map->map_flags & BPF_F_MMAPABLE) ||
	    vma->vm_end <= vma->vm_start)
		return -EINVAL;
	length = vma->vm_end - vma->vm_start;
	if ((vma->vm_start & (PAGE_SIZE - 1)) || (length & (PAGE_SIZE - 1)))
		return -EINVAL;
	/* Bound pgoff before shifting: addition/multiplication must not wrap. */
	if (vma->vm_pgoff > (value_bytes >> PAGE_SHIFT))
		return -EINVAL;
	offset = (u64)vma->vm_pgoff << PAGE_SHIFT;
	if (length > value_bytes - offset)
		return -EINVAL;

	return remap_vmalloc_range(vma, array_map_vmalloc_addr(array),
				   vma->vm_pgoff + header_pages);
}
