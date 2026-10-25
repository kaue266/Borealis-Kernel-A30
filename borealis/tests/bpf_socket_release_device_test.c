/* SPDX-License-Identifier: GPL-2.0-only
 * Candidate-only diagnostic. Attach only in a newly created isolated cgroup.
 * The parent never joins it; only our child creates/closes test UDP sockets.
 * No root-cgroup attachments, pinned objects, reboots or partition writes.
 */
#include "bpf_probe_runtime.h"
#include "bpf_probe_fs_flags.h"
#include <linux/magic.h>
#include <asm/statfs.h>

#define AF_INET 2
#define AF_INET6 10
#define SOCK_DGRAM 2
#define SOL_SOCKET 1
#define SO_COOKIE 57
struct result { uint64_t count, cookie; };
static char directory[160];
static int directory_created, directory_fd = -1, map_fd = -1, prog_fd = -1;
static const char *base;

static int bpf_command(int command, union bpf_attr *attr)
{
	return syscall(__NR_bpf, command, attr, sizeof(*attr));
}
static int open_path(const char *path, int flags)
{
	return probe_call(__NR_openat, AT_FDCWD, (long)path, flags | O_CLOEXEC, 0, 0, 0);
}
static int cleanup(void)
{
	int ok = 0;
	if (prog_fd >= 0) {
		union bpf_attr attr = {0};
		attr.target_fd = directory_fd;
		attr.attach_type = BPF_CGROUP_INET_SOCK_RELEASE;
		if (bpf_command(BPF_PROG_DETACH, &attr) != 0) ok = -1;
		close(prog_fd);
		prog_fd = -1;
	}
	if (map_fd >= 0) close(map_fd);
	if (directory_fd >= 0) close(directory_fd);
	if (directory_created && probe_call(__NR_unlinkat, AT_FDCWD, (long)directory, AT_REMOVEDIR, 0, 0, 0) != 0)
		ok = -1;
	return ok;
}
static int fail(const char *operation)
{
	int saved_errno = errno;
	if (cleanup() != 0) printf("Cleanup incomplete for isolated group %s; no candidate approval\n", directory);
	printf("FAIL operation=%s errno=%d; candidate network validation remains incomplete\n", operation, saved_errno);
	return 1;
}
static int create_group(void)
{
	const char *roots[] = {"/sys/fs/cgroup/unified", "/sys/fs/cgroup", "/dev/cg2_bpf"};
	for (size_t i = 0; i < sizeof(roots) / sizeof(roots[0]); i++) {
		int fd = open_path(roots[i], O_RDONLY | O_DIRECTORY);
		if (fd < 0) continue;
		struct statfs fs = {0};
		int ok = probe_call(__NR_fstatfs, fd, (long)&fs, 0, 0, 0, 0) == 0 && fs.f_type == CGROUP2_SUPER_MAGIC;
		close(fd);
		if (ok) { base = roots[i]; break; }
	}
	if (!base) return -1;
	size_t n = 0;
	for (; base[n]; n++) directory[n] = base[n];
	const char suffix[] = "/borealis-bpf-release-";
	for (size_t i = 0; i < sizeof(suffix) - 1; i++) directory[n++] = suffix[i];
	long pid = probe_call(__NR_getpid, 0, 0, 0, 0, 0, 0);
	if (pid <= 0) return -1;
	char digits[32];
	size_t count = 0;
	do { digits[count++] = '0' + pid % 10; pid /= 10; } while (pid);
	while (count) directory[n++] = digits[--count];
	directory[n] = 0;
	if (probe_call(__NR_mkdirat, AT_FDCWD, (long)directory, 0700, 0, 0, 0) != 0)
		return -1; /* Never reuse/remove a pre-existing directory. */
	directory_created = 1;
	directory_fd = open_path(directory, O_RDONLY | O_DIRECTORY);
	return directory_fd < 0 ? -1 : 0;
}

#define INSN(c,d,s,o,i) ((struct bpf_insn){.code=(c),.dst_reg=(d),.src_reg=(s),.off=(o),.imm=(i)})
static int attach_program(int return_value)
{
	/* ctx -> cookie, then update a two-u64 array entry. No socket references
	 * escape the hook. The NULL-map-value branch also returns the given code.
	 */
	struct bpf_insn insns[] = {
		INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_get_socket_cookie),
		INSN(BPF_ALU64 | BPF_MOV | BPF_X, 7, 0, 0, 0),
		INSN(BPF_ST | BPF_W | BPF_MEM, 10, 0, -4, 0),
		INSN(BPF_LD | BPF_DW | BPF_IMM, 1, BPF_PSEUDO_MAP_FD, 0, map_fd),
		INSN(0, 0, 0, 0, 0),
		INSN(BPF_ALU64 | BPF_MOV | BPF_X, 2, 10, 0, 0),
		INSN(BPF_ALU64 | BPF_ADD | BPF_K, 2, 0, 0, -4),
		INSN(BPF_JMP | BPF_CALL, 0, 0, 0, BPF_FUNC_map_lookup_elem),
		INSN(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 4, 0),
		INSN(BPF_LDX | BPF_DW | BPF_MEM, 1, 0, 0, 0),
		INSN(BPF_ALU64 | BPF_ADD | BPF_K, 1, 0, 0, 1),
		INSN(BPF_STX | BPF_DW | BPF_MEM, 0, 1, 0, 0),
		INSN(BPF_STX | BPF_DW | BPF_MEM, 0, 7, 8, 0),
		INSN(BPF_ALU64 | BPF_MOV | BPF_K, 0, 0, 0, return_value),
		INSN(BPF_JMP | BPF_EXIT, 0, 0, 0, 0),
	};
	char log[8192] = {0};
	union bpf_attr attr = {0};
	attr.prog_type = BPF_PROG_TYPE_CGROUP_SOCK;
	attr.expected_attach_type = BPF_CGROUP_INET_SOCK_RELEASE;
	attr.insn_cnt = sizeof(insns) / sizeof(insns[0]);
	attr.insns = (uintptr_t)insns;
	attr.license = (uintptr_t)"GPL";
	attr.log_level = 1;
	attr.log_size = sizeof(log);
	attr.log_buf = (uintptr_t)log;
	prog_fd = bpf_command(BPF_PROG_LOAD, &attr);
	if (prog_fd < 0) { printf("Verifier: %s\n", log); return -1; }
	memset(&attr, 0, sizeof(attr));
	attr.target_fd = directory_fd;
	attr.attach_bpf_fd = prog_fd;
	attr.attach_type = BPF_CGROUP_INET_SOCK_RELEASE;
	return bpf_command(BPF_PROG_ATTACH, &attr);
}
static int check_socket(int family, uint64_t expected_count)
{
	int fd = probe_call(__NR_socket, family, SOCK_DGRAM | O_CLOEXEC, 0, 0, 0, 0);
	if (fd < 0) return -1;
	uint64_t cookie = 0;
	uint32_t cookie_bytes = sizeof(cookie);
	int get = probe_call(__NR_getsockopt, fd, SOL_SOCKET, SO_COOKIE, (long)&cookie, (long)&cookie_bytes, 0);
	int closed = close(fd);
	if (get != 0 || closed != 0 || !cookie || cookie_bytes != sizeof(cookie)) return -1;
	union bpf_attr attr = {0};
	uint32_t key = 0;
	struct result result = {0};
	attr.map_fd = map_fd;
	attr.key = (uintptr_t)&key;
	attr.value = (uintptr_t)&result;
	if (bpf_command(BPF_MAP_LOOKUP_ELEM, &attr) != 0) return -1;
	if (result.count != expected_count || result.cookie != cookie) { errno = EINVAL; return -1; }
	return 0;
}
static int run_child(void)
{
	int fd = probe_call(__NR_openat, directory_fd, (long)"cgroup.procs", O_WRONLY | O_CLOEXEC, 0, 0, 0);
	if (fd < 0) return -1;
	/* Move only this child into the isolated cgroup. */
	int moved = probe_call(__NR_write, fd, (long)"0\n", 2, 0, 0, 0);
	close(fd);
	if (moved != 2) return -1;
	if (check_socket(AF_INET, 1) != 0) { printf("Child IPv4 failure errno=%d\n", errno); return -1; }
	if (check_socket(AF_INET6, 2) != 0) { printf("Child IPv6 failure errno=%d\n", errno); return -1; }
	return 0;
}
int main(void)
{
	if (create_group() != 0) return fail("create isolated cgroup2");
	union bpf_attr attr = {0};
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(struct result);
	attr.max_entries = 1;
	map_fd = bpf_command(BPF_MAP_CREATE, &attr);
	if (map_fd < 0) return fail("create temporary counter map");
	for (int ret = 0; ret <= 1; ret++) {
		uint32_t key = 0;
		struct result zero = {0};
		memset(&attr, 0, sizeof(attr));
		attr.map_fd = map_fd;
		attr.key = (uintptr_t)&key;
		attr.value = (uintptr_t)&zero;
		if (bpf_command(BPF_MAP_UPDATE_ELEM, &attr) != 0) return fail("reset map");
		if (attach_program(ret) != 0) return fail("load/attach release program");
		pid_t child = fork();
		if (child < 0) return fail("fork isolated socket test");
		if (!child) { int code = run_child(); _exit(code == 0 ? 0 : 1); }
		int status = 0;
		pid_t waited;
		do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == 4); /* EINTR */
		if (waited != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			if (waited == child) errno = EINVAL;
			return fail("IPv4/IPv6 close and cookie comparison");
		}
		memset(&attr, 0, sizeof(attr));
		attr.target_fd = directory_fd;
		attr.attach_type = BPF_CGROUP_INET_SOCK_RELEASE;
		if (bpf_command(BPF_PROG_DETACH, &attr) != 0) return fail("detach test program");
		close(prog_fd);
		prog_fd = -1;
	}
	if (cleanup() != 0) { printf("FAIL: cleanup of isolated group %s errno=%d\n", directory, errno); return 1; }
	printf("PASS: loaded release programs returning 0/1 close IPv4/IPv6 sockets and report matching cookies; Android17 network validation remains pending\n");
	return 0;
}
