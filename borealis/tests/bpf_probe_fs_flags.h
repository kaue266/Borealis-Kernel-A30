/* SPDX-License-Identifier: GPL-2.0-only
 * Only the raw AArch64 file syscall flags needed by this freestanding probe.
 * The builder checks every value against the installed AOSP UAPI headers.
 * This avoids importing bionic's libc/TLS declarations into the raw runtime.
 */
#define O_RDONLY 0
#define O_WRONLY 1
#define O_DIRECTORY 040000
#define O_CLOEXEC 02000000
#define AT_FDCWD (-100)
#define AT_REMOVEDIR 0x200
