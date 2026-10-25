/* SPDX-License-Identifier: GPL-2.0-only
 * Shared array mapping adapted from Linux v5.10. R24U has no MAP_FREEZE,
 * BTF spin-lock or program-readonly map semantics; those remain rejected.
 */
void *bpf_map_area_mmapable_alloc(size_t size, int numa_node)
{
	/* Explicit vmalloc, zero padding and VM_USERMAP are mandatory. Avoid
	 * invoking the OOM killer on behalf of a failed map allocation.
	 */
	return __vmalloc_node_range(size, PAGE_SIZE, VMALLOC_START, VMALLOC_END,
		GFP_USER | __GFP_NOWARN | __GFP_NORETRY | __GFP_ZERO, PAGE_KERNEL,
		VM_USERMAP, numa_node, __builtin_return_address(0));
}

static int bpf_map_mmap(struct file *filp, struct vm_area_struct *vma)
{
	struct bpf_map *map = filp->private_data;

	if (!map->ops->map_mmap)
		return -EOPNOTSUPP;
	if (!(vma->vm_flags & VM_SHARED))
		return -EINVAL;
	if (vma->vm_flags & VM_EXEC)
		return -EACCES;
	if (!(filp->f_mode & FMODE_READ) ||
	    ((vma->vm_flags & VM_WRITE) && !(filp->f_mode & FMODE_WRITE)))
		return -EACCES;

	vma->vm_flags &= ~VM_MAYEXEC;
	if (!(vma->vm_flags & VM_WRITE))
		vma->vm_flags &= ~VM_MAYWRITE;
	/* Generic mmap/fork/split paths hold vm_file, which owns the map ref.
	 * Closing the fd cannot release the map until the last VMA is gone.
	 * No writecnt/freeze callbacks are needed without MAP_FREEZE support.
	 */
	return map->ops->map_mmap(map, vma);
}
