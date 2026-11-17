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
#include <linux/file.h>
#include <linux/mount.h>
#include <linux/magic.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/version.h>
#include <asm/unistd.h>

#include "arch.h"
#include "klog.h"
#include "hook/syscall_hook.h"
#include "infra/bst_hide.h"
#include "infra/symbol_resolver.h"

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
	/* The initrd rc files were renamed to ovt*, which is our token rather
	 * than BlueStacks', but a stock image has neither name. */
	"init.ovt.rc",
	"ueventd.ovt.rc",
	/* Bind payload, copied out of /boot/ovtpatch at boot so that mountinfo
	 * quotes a mundane source path.  Generic names, but they only ever hide
	 * a directory entry from application uids. */
	".cfg",
	".cfg_idc",
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
	"/init.ovt.rc",
	"/ueventd.ovt.rc",
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
	 * visible: it belongs to BlueStacks, not to us.  The bind payload lives
	 * under a stock AOSP ramdisk directory so that the source path quoted in
	 * /proc/<pid>/mountinfo (the root field of a bind mount) reads as
	 * something ordinary. */
	"/second_stage_resources/.cfg",
	"/second_stage_resources/.cfg_idc",
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
	"/second_stage_resources/.cfg/",
	"/second_stage_resources/.cfg_idc/",
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
/* /proc/<pid>/{cpuinfo,version,status}                                */
/* ------------------------------------------------------------------ */

/*
 * /proc/cpuinfo on this image reports CPU implementer 0x61 (Apple) with the
 * ARMv8.6 feature set, because the guest really is running on Apple silicon
 * through qemu.  A real SM-G998B (Exynos 2100) is ARMv8.2-A with one Cortex-X1,
 * three Cortex-A78 and four Cortex-A55 cores, implementer 0x41.  Detection
 * SDKs read this file (and getauxval on the same data) directly, so the whole
 * file is served from a synthesised copy instead of being patched field by
 * field.
 */
#define BST_CPUINFO_FEATURES                                                              \
	"fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm" \
	" lrcpc dcpop asimddp sha3"

/* The version tail shared by /proc/version and uname(2).  The build host and
 * timezone are the giveaway - the guest kernel says nobody@android-build and
 * IST, a Samsung kernel says a dpi@ build host and KST. */
#define BST_UTS_VERSION "#1 SMP PREEMPT Thu Sep 10 04:12:26 KST 2026"

static const char bst_version_text[] =
	"Linux version 5.15.137-00001-gfdae1bb0ce90 (dpi@SWDG2521)"
	" (Android (8490178, based on r450784d) clang version 14.0.6"
	" (https://android.googlesource.com/toolchain/llvm-project"
	" 4c603efb0cca074e9238af8b4106c30add4418f6), LLD 14.0.6) "
	BST_UTS_VERSION "\n";

static char *bst_cpuinfo;
static size_t bst_cpuinfo_len;

static void __init bst_build_cpuinfo(void)
{
	static const unsigned int part[8] = {
		0xd44, 0xd41, 0xd41, 0xd41, 0xd05, 0xd05, 0xd05, 0xd05,
	};
	const size_t cap = 2048;
	char *p;
	int i;

	bst_cpuinfo = kmalloc(cap, GFP_KERNEL);
	if (!bst_cpuinfo)
		return;

	p = bst_cpuinfo;
	for (i = 0; i < 8; i++) {
		p += scnprintf(p, cap - (size_t)(p - bst_cpuinfo),
			       "processor\t: %d\n"
			       "BogoMIPS\t: %s\n"
			       "Features\t: " BST_CPUINFO_FEATURES "\n"
			       "CPU implementer\t: 0x41\n"
			       "CPU architecture: 8\n"
			       "CPU variant\t: 0x1\n"
			       "CPU part\t: 0x%x\n"
			       "CPU revision\t: 1\n"
			       "\n",
			       i, i < 4 ? "48.00" : "38.40", part[i]);
	}
	bst_cpuinfo_len = (size_t)(p - bst_cpuinfo);
}

/* Serve a read() out of a synthesised buffer, honouring the file position so
 * that a caller looping over small reads still sees the whole text. */
static noinline long bst_serve_text(struct file *file, char __user *ubuf,
				    size_t count, const char *text, size_t len)
{
	loff_t pos = file->f_pos;
	size_t n;

	if (pos < 0 || (size_t)pos >= len)
		return 0;

	n = len - (size_t)pos;
	if (n > count)
		n = count;

	if (copy_to_user(ubuf, text + (size_t)pos, n))
		return -EFAULT;

	file->f_pos = pos + n;
	return (long)n;
}

static void bst_fix_status(char *buf, long len)
{
	/* Same-length rewrites: the guest zygote is built without seccomp, so
	 * every app process reports Seccomp 0 with no filter installed. */
	static const char from[] = "Seccomp:\t0\n";
	static const char to[] = "Seccomp:\t2\n";
	static const char ffrom[] = "Seccomp_filters:\t0\n";
	static const char fto[] = "Seccomp_filters:\t1\n";
	long i;

	for (i = 0; i + (long)sizeof(from) - 1 <= len; i++) {
		if (!memcmp(buf + i, from, sizeof(from) - 1))
			memcpy(buf + i, to, sizeof(from) - 1);
	}
	for (i = 0; i + (long)sizeof(ffrom) - 1 <= len; i++) {
		if (!memcmp(buf + i, ffrom, sizeof(ffrom) - 1))
			memcpy(buf + i, fto, sizeof(ffrom) - 1);
	}
}

static DEFINE_MUTEX(bst_status_lock);
static char bst_status_buf[4096];

static syscall_fn_t bst_orig_read;
static long bst_sys_read(const struct pt_regs *regs)
{
	unsigned int fd = PT_REGS_SYSCALL_PARM1(regs);
	char __user *ubuf = (char __user *)PT_REGS_PARM2(regs);
	size_t count = (size_t)PT_REGS_PARM3(regs);
	const char *name;
	struct file *file;
	long ret;

	if (likely(!bst_hide_enabled) || likely(bst_uid_trusted()) || !ubuf || !count)
		return bst_orig_read(regs);

	rcu_read_lock();
	file = fget(fd);
	rcu_read_unlock();
	if (!file)
		return bst_orig_read(regs);

	if (file->f_path.mnt->mnt_sb->s_magic != PROC_SUPER_MAGIC)
		goto plain;

	name = file->f_path.dentry->d_name.name;

	if (!strcmp(name, "cpuinfo") && bst_cpuinfo) {
		ret = bst_serve_text(file, ubuf, count, bst_cpuinfo, bst_cpuinfo_len);
		fput(file);
		return ret;
	}
	if (!strcmp(name, "version")) {
		ret = bst_serve_text(file, ubuf, count, bst_version_text,
				     sizeof(bst_version_text) - 1);
		fput(file);
		return ret;
	}
	if (!strcmp(name, "status")) {
		ret = bst_orig_read(regs);
		if (ret > 0 && ret <= (long)sizeof(bst_status_buf)) {
			mutex_lock(&bst_status_lock);
			if (!copy_from_user(bst_status_buf, ubuf, ret)) {
				bst_fix_status(bst_status_buf, ret);
				if (copy_to_user(ubuf, bst_status_buf, ret))
					ret = -EFAULT;
			}
			mutex_unlock(&bst_status_lock);
		}
		fput(file);
		return ret;
	}

plain:
	fput(file);
	return bst_orig_read(regs);
}

/*
 * uname(2) reads the same utsname the kernel prints in /proc/version through
 * linux_proc_banner, but only the version tail is inside the utsname; the
 * builder string lives in a rodata banner.  Rewriting the tail keeps uname()
 * and /proc/version consistent with the text served above.
 */
static void __init bst_rewrite_utsname(void)
{
	char *base = (char *)find_kernel_symbol_exact("init_uts_ns");
	char *ver;
	int off;

	if (!base)
		return;

	for (off = 0; off < 256; off++) {
		if (!strcmp(base + off, "Linux"))
			break;
	}
	if (off >= 256) {
		pr_info("hide: init_uts_ns layout not recognised, left alone\n");
		return;
	}

	/* struct new_utsname is six NUL terminated 65 byte fields; the kernel
	 * initialises version from UTS_VERSION, which starts with '#'. */
	ver = base + off + 3 * 65;
	if (ver[0] != '#') {
		pr_info("hide: utsname version field unexpected, left alone\n");
		return;
	}

	memset(ver, 0, 65);
	strscpy(ver, BST_UTS_VERSION, 65);
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
	/* Installed after ksud's own read hook (call order in kernelsu_init), so
	 * bst_orig_read is ksud's wrapper and the two chain instead of clobbering
	 * each other. */
	if (ksu_syscall_table[__NR_read] != (void *)bst_sys_read)
		ksu_syscall_table_hook(__NR_read, bst_sys_read, &bst_orig_read);
#ifdef __NR_openat2
	ksu_syscall_table_hook(BST_NR_OPENAT2, bst_sys_openat2, &bst_orig_openat2);
#endif
#ifdef __NR_faccessat2
	ksu_syscall_table_hook(BST_NR_FACCESSAT2, bst_sys_faccessat2, &bst_orig_faccessat2);
#endif
#ifdef __NR_statx
	ksu_syscall_table_hook(BST_NR_STATX, bst_sys_statx, &bst_orig_statx);
#endif

	bst_build_cpuinfo();
	bst_rewrite_utsname();

	pr_info("bst_hide: layer 2 path adjudication + proc text installed\n");
}
