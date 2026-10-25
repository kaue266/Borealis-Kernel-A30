/* SPDX-License-Identifier: GPL-2.0-only
 * Minimal AArch64 syscall runtime for the isolated VM diagnostic.
 * Uses the AOSP UAPI; no libc, dynamic loader, TLS or persistent state.
 */
#ifndef BOREALIS_BPF_PROBE_RUNTIME_H
#define BOREALIS_BPF_PROBE_RUNTIME_H
#include <linux/bpf.h>
#include <asm/unistd.h>
#include <stdarg.h>

typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
typedef unsigned long uintptr_t;
typedef unsigned long size_t;
typedef long off_t;
typedef int pid_t;
#define UINT64_C(n) n##ULL
#define NULL ((void *)0)
#define EINVAL 22
#define PROT_READ 1
#define PROT_WRITE 2
#define PROT_EXEC 4
#define MAP_SHARED 1
#define MAP_PRIVATE 2
#define MAP_FAILED ((void *)-1)
#define _SC_PAGESIZE 1
#define WIFEXITED(s) (((s)&0x7f)==0)
#define WEXITSTATUS(s) (((s)>>8)&255)
static int probe_errno;
static long probe_page_size;
#define errno probe_errno

static long probe_call(long number, long a, long b, long c, long d, long e, long f)
{
	register long x0 __asm__("x0") = a, x1 __asm__("x1") = b, x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d, x4 __asm__("x4") = e, x5 __asm__("x5") = f;
	register long x8 __asm__("x8") = number;
	__asm__ volatile("svc 0" : "+r"(x0) : "r"(x1), "r"(x2), "r"(x3),
		"r"(x4), "r"(x5), "r"(x8) : "memory", "cc");
	if ((unsigned long)x0 >= (unsigned long)-4095) {
		errno = -x0;
		return -1;
	}
	return x0;
}
#define syscall(n,a,b,c) probe_call(n,(long)(a),(long)(b),(long)(c),0,0,0)
/* Large aggregate initializers may emit this symbol even without libc.
 * Export it and use volatile stores so its own loop cannot become a call.
 */
void *memset(void *p, int value, size_t count)
{
	volatile unsigned char *bytes = p;
	for (size_t i = 0; i < count; i++)
		bytes[i] = value;
	return p;
}
static void *mmap(void *addr, size_t bytes, int prot, int flags, int fd, off_t off)
{
	return (void *)probe_call(__NR_mmap, (long)addr, bytes, prot, flags, fd, off);
}
static int munmap(void *addr, size_t bytes)
{
	return probe_call(__NR_munmap, (long)addr, bytes, 0, 0, 0, 0);
}
static int mprotect(void *addr, size_t bytes, int prot)
{
	return probe_call(__NR_mprotect, (long)addr, bytes, prot, 0, 0, 0);
}
static int close(int fd)
{
	return probe_call(__NR_close, fd, 0, 0, 0, 0, 0);
}
static pid_t fork(void)
{
	/* SIGCHLD without CLONE_VM gives fork semantics on AArch64. */
	return probe_call(__NR_clone, 17, 0, 0, 0, 0, 0);
}
static pid_t waitpid(pid_t pid, int *status, int options)
{
	return probe_call(__NR_wait4, pid, (long)status, options, 0, 0, 0);
}
static long sysconf(int option)
{
	if (option != _SC_PAGESIZE)
		return -1;
	return probe_page_size;
}
static void _exit(int code) __attribute__((noreturn));
static void _exit(int code)
{
	probe_call(__NR_exit, code, 0, 0, 0, 0, 0);
	for (;;) {}
}
static void exit(int code) __attribute__((noreturn));
static void exit(int code)
{
	_exit(code);
}
static int printf(const char *format, ...)
{
	char output[512];
	size_t size = 0;
	va_list args;
	va_start(args, format);
	while (*format && size < sizeof(output) - 1) {
		if (*format != '%') {
			output[size++] = *format++;
			continue;
		}
		format++;
		if (*format == 's') {
			const char *s = va_arg(args, const char *);
			while (*s && size < sizeof(output) - 1)
				output[size++] = *s++;
			format++;
		} else {
			long value;
			if (*format == 'l') {
				format++;
				value = va_arg(args, long);
			} else {
				value = va_arg(args, int);
			}
			if (*format++ != 'd')
				_exit(2);
			unsigned long magnitude = value < 0 ? 0UL - (unsigned long)value : (unsigned long)value;
			char digits[32];
			size_t count = 0;
			do { digits[count++] = '0' + magnitude % 10; magnitude /= 10; } while (magnitude);
			if (value < 0)
				digits[count++] = '-';
			while (count && size < sizeof(output) - 1)
				output[size++] = digits[--count];
		}
	}
	va_end(args);
	size_t done = 0;
	while (done < size) {
		long written = probe_call(__NR_write, 1, (long)(output + done), size - done, 0, 0, 0);
		if (written <= 0)
			return -1;
		done += written;
	}
	return size;
}
int main(void);
void probe_entry(const unsigned long *initial_stack) __attribute__((noreturn));
void probe_entry(const unsigned long *initial_stack)
{
	const unsigned long *next = initial_stack + initial_stack[0] + 2;
	while (*next) next++; /* Skip envp. */
	next++;
	for (; next[0]; next += 2) {
		if (next[0] == 6) /* AT_PAGESZ */
			probe_page_size = next[1];
	}
	_exit(main());
}
__asm__(".global _start\n_start:\nmov x0, sp\nbl probe_entry\n");
#endif
