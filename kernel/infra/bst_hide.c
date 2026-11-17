// SPDX-License-Identifier: GPL-2.0
/*
 * bst_hide.c - answer "does this entity exist?" for a BlueStacks Air guest
 * whose ramdisk renames the emulator's own artefacts.
 *
 * The image cannot be made clean by removal.  /fstab.bst is opened by the
 * stock init before any fallback path is considered (renaming it is a
 * first-stage mount failure, verified the hard way), bstime drives the
 * typing bridge and the *.bst.so modules are loaded by services that run as
 * dedicated uids, so layer 1 of the plan leaves them on disk and this file
 * answers -ENOENT for the callers that must not learn what they are running
 * on:
 *
 *   - openat, openat2, faccessat, faccessat2, newfstatat (stat/lstat/fstatat)
 *     and statx deny with -ENOENT.  Never -EACCES: a detector reads EACCES as
 *     "the file is there, I am merely not allowed in", which is the opposite
 *     of what we want.  ACE's C03 dual-path check compares libc against raw
 *     svc, and a kernel-side answer sits below both of them.
 *   - getdents64 drops the names from directory listings, so an enumeration of
 *     /, /system/bin, /system/lib64/hw or /data cannot see them either.
 *
 * Who still sees the truth: every uid below 10000 - root, system, adb shell,
 * and each native service or HAL uid.  Only application uids are lied to,
 * which is exactly the context a detection SDK runs in.  init, ueventd,
 * bstime, the HAL modules and the KernelSU plumbing keep working unchanged.
 *
 * Matching is exact, never a "bst" substring: that token also occurs in
 * substream and tombstoned.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/cred.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ptrace.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/version.h>
#include <asm/unistd.h>

#include "arch.h"
#include "klog.h"
#include "hook/syscall_hook.h"
#include "infra/bst_hide.h"

/* Syscall numbers, with the arch table values as fallbacks.  asm-generic
 * spells some of these through an intermediate __NR3264_* name, so the
 * explicit value keeps the build honest on a tree where the alias is not
 * visible. */
#ifdef __NR_newfstatat
#define BST_NR_FSTATAT __NR_newfstatat
#else
#define BST_NR_FSTATAT 79 /* sys_newfstatat */
#endif
#ifdef __NR_openat2
#define BST_NR_OPENAT2 __NR_openat2
#else
#define BST_NR_OPENAT2 437
#endif
#ifdef __NR_faccessat2
#define BST_NR_FACCESSAT2 __NR_faccessat2
#else
#define BST_NR_FACCESSAT2 439
#endif
#ifdef __NR_statx
#define BST_NR_STATX __NR_statx
#else
#define BST_NR_STATX 291
#endif

/* Longest path component set we look at.  Only the leading bytes of a user
 * path are ever needed: every hidden name is well inside this window. */
#define BST_PATH_MAX 256

/* getdents64 buffers above this are passed through unfiltered instead of
 * allocating a kernel bounce buffer for them. */
#define BST_DIRENT_MAX 32768

/* Application uids start here (AID_APP).  Everything below is a native uid
 * that legitimately opens the renamed files. */
#define BST_TRUSTED_UID_MAX 10000

static bool bst_hide_enabled __read_mostly = true;
module_param_named(bst_hide, bst_hide_enabled, bool, 0644);

/* Chatty mode: log each denial.  Off by default - openat runs far too often
 * for that, and the log is one of the surfaces ACE reads. */
static bool bst_hide_log __read_mostly;
module_param_named(bst_hide_log, bst_hide_log, bool, 0644);

struct bst_dirent64 {
	u64 d_ino;
	s64 d_off;
	u16 d_reclen;
	u8 d_type;
	char d_name[];
};

/* Names that must not appear in a listing and must not resolve as a
 * basename.  Exact, case sensitive. */
static const char *const bst_hide_names[] = {
	"fstab.bst",
	"out_bstconf",
	"bstconf",
	"bstime",
	"bstshutdown",
	"bstshutdown_core",
	"bstk",
	"bstsetup.env",
	"bstsetconf.sh",
	".propfile",
	".bluestacks.prop",
	".abipropfile",
	".bstconf.prop",
	".bprop",
	"BlueStacks_Virtual_Touch.idc",
};

/* Whole paths that must resolve to -ENOENT. */
static const char *const bst_hide_paths[] = {
	"/fstab.bst",
	"/system/out_bstconf",
	"/system/out_bstconf/bstconf",
	"/system/bin/bstime",
	"/system/bin/bstshutdown",
	"/system/bin/bstshutdown_core",
	"/system/xbin/bstk",
	"/system/usr/idc/BlueStacks_Virtual_Touch.idc",
	"/system/priv-app/com.bluestacks.settings",
	"/system/priv-app/com.bluestacks.BstCommandProcessor",
	"/data/.propfile",
	"/data/.bluestacks.prop",
	"/data/.abipropfile",
	"/data/.bstconf.prop",
	"/data/.bprop",
	"/data/data/com.bluestacks.settings",
	"/data/data/com.bluestacks.BstCommandProcessor",
	/* The ramdisk-side of the deblur layer.  /boot/android itself stays
	 * visible: it belongs to BlueStacks, not to us. */
	"/boot/ovtpatch",
	"/boot/ovtmods",
	"/boot/ovtconf.sh",
	"/boot/ovtsetup.env",
	"/boot/stage2.sh",
	"/boot/init",
	"/boot/bin",
	"/boot/idc",
};

/* Directory trees that must not resolve at all. */
static const char *const bst_hide_prefixes[] = {
	"/system/out_bstconf/",
	"/system/priv-app/com.bluestacks.settings/",
	"/system/priv-app/com.bluestacks.BstCommandProcessor/",
	"/data/data/com.bluestacks.settings/",
	"/data/data/com.bluestacks.BstCommandProcessor/",
	"/boot/ovtpatch/",
	"/boot/ovtmods/",
	"/boot/bin/",
	"/boot/idc/",
};

static const char *bst_basename(const char *path)
{
	const char *slash = strrchr(path, '/');

	return slash ? slash + 1 : path;
}

static bool bst_name_hidden(const char *name)
{
	size_t i, len;

	if (!name || !name[0])
		return false;

	len = strlen(name);
	/* The HAL modules are the one family with a shared suffix. */
	if (len > 4 && !strcmp(name + len - 4, ".bst"))
		return true;
	if (len > 7 && !strcmp(name + len - 7, ".bst.so"))
		return true;

	for (i = 0; i < ARRAY_SIZE(bst_hide_names); i++) {
		if (!strcmp(name, bst_hide_names[i]))
			return true;
	}

	return false;
}

static bool bst_path_hidden(const char *path)
{
	size_t i, plen;

	for (i = 0; i < ARRAY_SIZE(bst_hide_paths); i++) {
		if (!strcmp(path, bst_hide_paths[i]))
			return true;
	}

	for (i = 0; i < ARRAY_SIZE(bst_hide_prefixes); i++) {
		plen = strlen(bst_hide_prefixes[i]);
		if (!strncmp(path, bst_hide_prefixes[i], plen))
			return true;
	}

	/* A relative open through a dirfd ("openat(dirfd, \"bstime\", ...)")
	 * carries no directory part, so the basename test is all there is. */
	return bst_name_hidden(bst_basename(path));
}

static inline bool bst_uid_trusted(void)
{
	uid_t uid = current_uid().val;

	return uid < BST_TRUSTED_UID_MAX;
}

/*
 * Shared front half for the path-taking syscalls: @uname is the user pointer
 * to the pathname, @orig the entry we replaced.  Returns the original
 * syscall's value unless the path is one of ours and the caller is an app.
 */
static noinline long bst_guard_path(const char __user *uname, syscall_fn_t orig,
				    const struct pt_regs *regs)
{
	char path[BST_PATH_MAX];

	if (likely(!bst_hide_enabled) || likely(bst_uid_trusted()) || !uname)
		return orig(regs);

	memset(path, 0, sizeof(path));
	if (strncpy_from_user_nofault(path, uname, sizeof(path)) < 0)
		return orig(regs);

	/* Cheap rejection first: a path that carries none of these bytes
	 * cannot match anything in the tables.  ("prop" rather than ".propfile"
	 * so that /data/.bluestacks.prop is not filtered out here.) */
	if (likely(!strstr(path, "bst") && !strstr(path, "prop") &&
		   !strstr(path, "idc") && strncmp(path, "/boot/", 6) != 0))
		return orig(regs);

	if (likely(!bst_path_hidden(path)))
		return orig(regs);

	if (unlikely(bst_hide_log))
		pr_info("hide: ENOENT %s (uid %u)\n", path, current_uid().val);

	return -ENOENT;
}

static syscall_fn_t bst_orig_openat;
static long bst_sys_openat(const struct pt_regs *regs)
{
	return bst_guard_path((const char __user *)PT_REGS_PARM2(regs),
			      bst_orig_openat, regs);
}

#ifdef __NR_openat2
static syscall_fn_t bst_orig_openat2;
static long bst_sys_openat2(const struct pt_regs *regs)
{
	return bst_guard_path((const char __user *)PT_REGS_PARM2(regs),
			      bst_orig_openat2, regs);
}
#endif

static syscall_fn_t bst_orig_faccessat;
static long bst_sys_faccessat(const struct pt_regs *regs)
{
	return bst_guard_path((const char __user *)PT_REGS_PARM2(regs),
			      bst_orig_faccessat, regs);
}

#ifdef __NR_faccessat2
static syscall_fn_t bst_orig_faccessat2;
static long bst_sys_faccessat2(const struct pt_regs *regs)
{
	return bst_guard_path((const char __user *)PT_REGS_PARM2(regs),
			      bst_orig_faccessat2, regs);
}
#endif

static syscall_fn_t bst_orig_newfstatat;
static long bst_sys_newfstatat(const struct pt_regs *regs)
{
	return bst_guard_path((const char __user *)PT_REGS_PARM2(regs),
			      bst_orig_newfstatat, regs);
}

#ifdef __NR_statx
static syscall_fn_t bst_orig_statx;
static long bst_sys_statx(const struct pt_regs *regs)
{
	return bst_guard_path((const char __user *)PT_REGS_PARM2(regs),
			      bst_orig_statx, regs);
}
#endif

/* ------------------------------------------------------------------ */
/* getdents64                                                          */
/* ------------------------------------------------------------------ */

static bool bst_dirname_hidden(const char *name, unsigned int room)
{
	char tmp[BST_PATH_MAX];
	size_t len;

	if (!room)
		return false;

	len = strnlen(name, room);
	if (len >= sizeof(tmp))
		len = sizeof(tmp) - 1;
	memcpy(tmp, name, len);
	tmp[len] = '\0';

	if (bst_name_hidden(tmp))
		return true;
	/* com.bluestacks.* application packages are hidden from package
	 * queries by the framework already; keep them out of raw listings as
	 * well so the two views agree. */
	if (!strncmp(tmp, "com.bluestacks.", 15))
		return true;

	return false;
}

/*
 * Compact a getdents64 buffer in place, dropping hidden entries.  Returns the
 * new length; a malformed record makes the caller fall back to the original
 * buffer rather than risk corrupting a listing.
 */
static long bst_filter_dirents(char *buf, long len)
{
	const unsigned int hdr = offsetof(struct bst_dirent64, d_name);
	long src = 0, dst = 0;

	/* Validate before touching anything: a partial compaction followed by
	 * a malformed record would leave the caller with a buffer it would
	 * then be told to keep. */
	for (src = 0; src + (long)hdr <= len;) {
		struct bst_dirent64 *de = (struct bst_dirent64 *)(buf + src);

		if (de->d_reclen < hdr + 2 || src + (long)de->d_reclen > len)
			return len;
		src += de->d_reclen;
	}

	for (src = 0; src < len;) {
		struct bst_dirent64 *de = (struct bst_dirent64 *)(buf + src);
		unsigned int reclen = de->d_reclen;

		if (bst_dirname_hidden(de->d_name, reclen - hdr)) {
			src += reclen;
			continue;
		}

		if (dst != src)
			memmove(buf + dst, buf + src, reclen);
		dst += reclen;
		src += reclen;
	}

	return dst;
}

static noinline long bst_guard_dirents(syscall_fn_t orig, const struct pt_regs *regs,
				       unsigned int count)
{
	char __user *ubuf = (char __user *)PT_REGS_PARM2(regs);
	char *kbuf;
	long ret, filtered;
	int tries;

	if (count == 0 || count > BST_DIRENT_MAX || !ubuf)
		return orig(regs);

	kbuf = kmalloc(count, GFP_KERNEL);
	if (!kbuf)
		return orig(regs);

	for (tries = 0; tries < 8; tries++) {
		ret = orig(regs);
		if (ret <= 0)
			goto out;

		/* The syscall must never report more than it was given room
		 * for; if it did, do not touch the buffer. */
		if ((unsigned long)ret > count)
			goto out;

		if (copy_from_user(kbuf, ubuf, ret))
			goto out;

		filtered = bst_filter_dirents(kbuf, ret);
		if (filtered == ret)
			goto out;

		if (filtered > 0) {
			if (!copy_to_user(ubuf, kbuf, filtered))
				ret = filtered;
			goto out;
		}

		/* Everything in this chunk was hidden.  Ask the file for the
		 * next chunk instead of reporting end-of-directory, otherwise
		 * a listing could stop early and hide real entries behind a
		 * block of ours. */
	}

	ret = 0;
out:
	kfree(kbuf);
	return ret;
}

static syscall_fn_t bst_orig_getdents64;
static long bst_sys_getdents64(const struct pt_regs *regs)
{
	if (likely(!bst_hide_enabled) || likely(bst_uid_trusted()))
		return bst_orig_getdents64(regs);

	return bst_guard_dirents(bst_orig_getdents64, regs,
				 (unsigned int)PT_REGS_PARM3(regs));
}

/* ------------------------------------------------------------------ */
/* install                                                             */
/* ------------------------------------------------------------------ */

void __init ksu_bst_hide_init(void)
{
	if (!ksu_syscall_table) {
		pr_err("bst_hide: syscall table unresolved, layer 2 disabled\n");
		return;
	}

	ksu_syscall_table_hook(__NR_openat, bst_sys_openat, &bst_orig_openat);
	ksu_syscall_table_hook(__NR_faccessat, bst_sys_faccessat, &bst_orig_faccessat);
	ksu_syscall_table_hook(BST_NR_FSTATAT, bst_sys_newfstatat, &bst_orig_newfstatat);
	ksu_syscall_table_hook(__NR_getdents64, bst_sys_getdents64, &bst_orig_getdents64);
#ifdef __NR_openat2
	ksu_syscall_table_hook(BST_NR_OPENAT2, bst_sys_openat2, &bst_orig_openat2);
#endif
#ifdef __NR_faccessat2
	ksu_syscall_table_hook(BST_NR_FACCESSAT2, bst_sys_faccessat2, &bst_orig_faccessat2);
#endif
#ifdef __NR_statx
	ksu_syscall_table_hook(BST_NR_STATX, bst_sys_statx, &bst_orig_statx);
#endif

	pr_info("bst_hide: layer 2 path adjudication installed\n");
}
