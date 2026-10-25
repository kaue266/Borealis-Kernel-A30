/* SPDX-License-Identifier: GPL-2.0-only
 * Ephemeral BPF array/VM diagnostic. No pinning or program attachment.
 * Run only during candidate-kernel validation; host compilation is not proof.
 */
#define _GNU_SOURCE
#ifdef BOREALIS_FREESTANDING
#include "bpf_probe_runtime.h"
#else
#include <errno.h>
#include <linux/bpf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

static int cases;
static void fail(const char *step)
{
	printf("{\"passed\":false,\"step\":\"%s\",\"errno\":%d,\"completed_cases\":%d}\n",
	       step, errno, cases);
	exit(1);
}

static int map_create(uint32_t entries, uint32_t flags)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint64_t);
	attr.max_entries = entries;
	attr.map_flags = BPF_F_MMAPABLE | flags;
	return syscall(__NR_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));
}

static uint64_t lookup(int fd, uint32_t key)
{
	union bpf_attr attr;
	uint64_t value = 0;
	memset(&attr, 0, sizeof(attr));
	attr.map_fd = fd;
	attr.key = (uintptr_t)&key;
	attr.value = (uintptr_t)&value;
	if (syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &attr, sizeof(attr)))
		fail("lookup_mapped_value");
	return value;
}

static void rejected_mapping(int fd, size_t bytes, int prot, int flags,
			     off_t offset, const char *step)
{
	void *area = mmap(NULL, bytes, prot, flags, fd, offset);
	if (area != MAP_FAILED) {
		munmap(area, bytes);
		errno = 0;
		fail(step);
	}
	cases++;
}

int main(void)
{
	long page = sysconf(_SC_PAGESIZE);
	if (page < 4096 || page > 65536 || page % sizeof(uint64_t)) {
		errno = EINVAL;
		fail("page_size");
	}
	size_t bytes = (size_t)page * 2;
	uint32_t entries = bytes / sizeof(uint64_t);
	int fd = map_create(entries, 0);
	if (fd < 0)
		fail("create_mmapable_array");
	cases++;
	volatile uint64_t *values = mmap(NULL, bytes, PROT_READ | PROT_WRITE,
					MAP_SHARED, fd, 0);
	if (values == MAP_FAILED)
		fail("map_shared_values");
	for (uint32_t i = 0; i < entries; i++) {
		if (values[i]) {
			errno = 0;
			fail("zeroed_values_metadata_excluded");
		}
	}
	cases++;
	values[0] = UINT64_C(0x5152535455565758);
	values[entries - 1] = UINT64_C(0x6162636465666768);
	if (lookup(fd, 0) != values[0] || lookup(fd, entries - 1) != values[entries - 1]) {
		errno = 0;
		fail("mapping_matches_map_storage");
	}
	cases++;
	void *second = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, page);
	if (second == MAP_FAILED)
		fail("map_second_value_page");
	if (((uint64_t *)second)[page / sizeof(uint64_t) - 1] != values[entries - 1]) {
		errno = 0;
		fail("page_offset_translation");
	}
	munmap(second, page);
	cases++;
	rejected_mapping(fd, page, PROT_READ, MAP_SHARED, bytes, "reject_past_last_page");
	rejected_mapping(fd, bytes + page, PROT_READ, MAP_SHARED, 0, "reject_oversized_mapping");
	rejected_mapping(fd, page, PROT_READ, MAP_PRIVATE, 0, "reject_private_mapping");
	rejected_mapping(fd, page, PROT_READ | PROT_EXEC, MAP_SHARED, 0, "reject_executable_mapping");

	void *readonly = mmap(NULL, page, PROT_READ, MAP_SHARED, fd, 0);
	if (readonly == MAP_FAILED)
		fail("readonly_mapping");
	if (!mprotect(readonly, page, PROT_READ | PROT_WRITE)) {
		errno = 0;
		fail("reject_readonly_write_upgrade");
	}
	if (!mprotect(readonly, page, PROT_READ | PROT_EXEC)) {
		errno = 0;
		fail("reject_readonly_exec_upgrade");
	}
	munmap(readonly, page);
	cases += 2;

	int rofd = map_create(entries, BPF_F_RDONLY);
	if (rofd < 0)
		fail("create_readonly_descriptor");
	readonly = mmap(NULL, page, PROT_READ, MAP_SHARED, rofd, 0);
	if (readonly == MAP_FAILED)
		fail("map_readonly_descriptor");
	rejected_mapping(rofd, page, PROT_READ | PROT_WRITE, MAP_SHARED, 0,
			 "reject_write_readonly_descriptor");
	munmap(readonly, page);
	close(rofd);
	cases++;

	/* The mapping must keep the map alive after its only fd is closed. */
	close(fd);
	if (values[0] != UINT64_C(0x5152535455565758)) {
		errno = 0;
		fail("mapping_after_fd_close");
	}
	cases++;
	pid_t child = fork();
	if (child < 0)
		fail("fork_mapped_array");
	if (!child) {
		values[0] = UINT64_C(0x7172737475767778);
		_exit(0);
	}
	int status = 0;
	if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status))
		fail("wait_forked_mapping");
	if (values[0] != UINT64_C(0x7172737475767778)) {
		errno = 0;
		fail("fork_shared_values_and_lifetime");
	}
	cases++;
	if (munmap((void *)values, bytes))
		fail("unmap_last_reference");
	cases++;
	printf("{\"passed\":true,\"cases\":%d,\"page_size\":%ld,\"maps_pinned\":false,\"programs_attached\":false}\n",
	       cases, page);
	return 0;
}
