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
#include <linux/fd.h>
#include <linux/fcntl.h>
#include <linux/mount.h>
#include <linux/mman.h>
#include <linux/magic.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <linux/version.h>
#include <linux/atomic.h>
#include <linux/signal.h>
#include <linux/sched/signal.h>
#include <linux/dcache.h>
#include <linux/mm.h>
#include <linux/limits.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
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

/* Two of the L4 layers are speculative: they hide or fabricate things a
 * detector may or may not look at, and a wrong guess can be worse than the
 * leak it covers (a name that is listed but will not stat is evidence of a
 * hide).  Both can therefore be switched at run time through /proc/ovtcfg,
 * which makes them A/B testable against the real detector instead of being
 * decided by argument. */
static bool bst_vm_hiding_enabled __read_mostly = true;
module_param_named(bst_vm, bst_vm_hiding_enabled, bool, 0644);

static bool bst_selinux_fake_enabled __read_mostly = true;
module_param_named(bst_selinux, bst_selinux_fake_enabled, bool, 0644);

/*
 * Diagnostic probe counter.  A detector decides what to report from a modest
 * number of kernel surfaces; finding out which ones a given build actually
 * looks at is otherwise guesswork, because the verdict UI shows only a
 * synopsis.  With bst_trace=1 an application uid's opens of the handful of
 * surfaces below are logged to dmesg, which makes the probe list of a run
 * readable.  It is a debugging aid, not a layer: this build ships it on so
 * that the probe list of a detector run can be read straight out of dmesg,
 * capped at 2000 lines so a long uptime cannot flood the ring buffer.
 */
#define BST_TRACE_MAX 2000
static bool bst_trace_enabled __read_mostly;
module_param_named(bst_trace, bst_trace_enabled, bool, 0644);
static atomic_t bst_trace_hits = ATOMIC_INIT(0);

static const char *const bst_trace_paths[] = {
	"/proc/cmdline",
	"/proc/config.gz",
	"/proc/device-tree",
	"/sys/fs/selinux",
	"/sys/devices/platform",
	"/sys/devices/system/cpu",
	"/sys/class/tty",
	"/sys/block",
	"/sys/bus",
	"/sys/firmware",
	"/dev/vsock",
	"/dev/vhost",
	"/dev/ovtgmd",
	"/dev/__properties__",
};

static void bst_trace_path(const char *path)
{
	size_t i;

	if (likely(!bst_trace_enabled))
		return;
	if (atomic_inc_return(&bst_trace_hits) > BST_TRACE_MAX) {
		bst_trace_enabled = false;
		pr_info("hide: probe trace capped\n");
		return;
	}

	for (i = 0; i < ARRAY_SIZE(bst_trace_paths); i++) {
		if (!strncmp(path, bst_trace_paths[i],
			     strlen(bst_trace_paths[i]))) {
			pr_info("trace: app %s (uid %u)\n", path,
				current_uid().val);
			return;
		}
	}
}

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


/* BlueStacks writes its per-package model table and a handful of tuning
 * files into /data/downloads/.tmp, mode 0644, so any application can read
 * them.  A stock device has none of them; the detector opens .modelProp in a
 * tight retry loop right before it decides to kill itself. */
static const char *const bst_bluestacks_files[] = {
	".modelProp",
	".bstMemorySizeApps",
	".bstXcpuApps",
	".bstXperfModeApps",
	".bstZeroMappedPageApps",
};

static bool bst_bluestacks_file(const char *name)
{
	size_t i;

	if (!name || !name[0])
		return false;

	for (i = 0; i < ARRAY_SIZE(bst_bluestacks_files); i++) {
		if (!strcmp(name, bst_bluestacks_files[i]))
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

/* ------------------------------------------------------------------ */
/* L4: virtualisation artefacts in sysfs and devtmpfs                  */
/* ------------------------------------------------------------------ */

/*
 * The guest boots on qemu's "virt" machine, so sysfs advertises hardware no
 * phone ever shipped: thirty-two virtio-mmio transports, an ARM pl011 UART
 * (ttyAMA0, which Android never has - Android phones use ttyMSM0/ttySAC0),
 * a pl031 RTC, a pl061 GPIO bank, a fw_cfg node, virtio block disks named
 * vda/vdb and a single generic PCIe host.  A detection SDK that enumerates
 * /sys/devices/platform, /sys/class/tty, /sys/bus or /sys/block sees the
 * hypervisor immediately, which is what the "Miscellaneous Check" family of
 * findings is about.
 *
 * Matching is by exact name or by one of the four qemu-specific suffixes,
 * never by a substring: "virtio" is also a legitimate real host bus on
 * virtualised cloud phones, and "pl011" appears in no other context.  The
 * checks only ever apply below /sys and /dev, so an application file that
 * happens to be called "vda" is unaffected.
 *
 * Everything is answered for application uids only - HALs, init and root
 * still enumerate the real tree, which keeps qemu's own device handling and
 * any root-level debugging intact.
 */
static const char *const bst_vm_names[] = {
	"ttyAMA0",
	"virtio",
	"reg-dummy",
	"snd-soc-dummy",
	"platform-framebuffer.0",
	"platform-bus@c000000",
	"Fixed MDIO bus.0",
	"0.flash",
	"4ff000000.pcie",
	"vhost-vsock",
};

static const char *const bst_vm_suffixes[] = {
	".pl011",
	".pl031",
	".pl061",
	".fw-cfg",
};

/* Not every 5.15 branch carries this one in linux/magic.h. */
#ifndef DEVTMPFS_MAGIC
#define DEVTMPFS_MAGIC 0x00001cd1
#endif

static bool bst_vm_name_hidden(const char *name)
{
	size_t i, len;

	if (!name || !name[0])
		return false;

	len = strlen(name);

	for (i = 0; i < ARRAY_SIZE(bst_vm_names); i++) {
		if (!strcmp(name, bst_vm_names[i]))
			return true;
	}

	for (i = 0; i < ARRAY_SIZE(bst_vm_suffixes); i++) {
		size_t slen = strlen(bst_vm_suffixes[i]);

		if (len > slen && !strcmp(name + len - slen, bst_vm_suffixes[i]))
			return true;
	}

	/* a000000.virtio_mmio ... a003e00.virtio_mmio, each with a virtioN
	 * child directory, plus the virtio bus they hang off. */
	if (strstr(name, ".virtio_mmio"))
		return true;

	/* virtio block disks: vda, vdb, ... (a phone shows mmcblk0/sda). */
	if (len >= 3 && name[0] == 'v' && name[1] == 'd' &&
	    name[2] >= 'a' && name[2] <= 'z') {
		size_t k = 3;

		while (name[k] >= '0' && name[k] <= '9')
			k++;
		if (!name[k])
			return true;
	}

	return false;
}

/*
 * Walk an absolute path component by component and reject it when any single
 * component is one of the machine model's names.  getdents64 uses the plain
 * name test on the entry instead, because it already knows the directory.
 */
static bool bst_vm_path_hidden(const char *path)
{
	char buf[BST_PATH_MAX];
	size_t n, i, start = 1;

	if (likely(!bst_vm_hiding_enabled))
		return false;

	if (strncmp(path, "/sys/", 5) != 0 && strncmp(path, "/dev/", 5) != 0)
		return false;

	n = strnlen(path, sizeof(buf) - 1);
	memcpy(buf, path, n);
	buf[n] = '\0';

	for (i = 1; i <= n; i++) {
		char save;

		if (buf[i] != '/' && buf[i] != '\0')
			continue;

		save = buf[i];
		buf[i] = '\0';
		if (bst_vm_name_hidden(buf + start)) {
			buf[i] = save;
			return true;
		}
		buf[i] = save;

		if (!save)
			break;
		start = i + 1;
	}

	return false;
}

static inline bool bst_uid_trusted(void)
{
	uid_t uid = current_uid().val;

	return uid < BST_TRUSTED_UID_MAX;
}

static void bst_ring_add(u16 nr, s64 a0, s64 a1, const char *path);

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

	bst_trace_path(path);
	bst_ring_add(1, 0, 0, path);

	/* L4 virtualisation artefacts.  Checked before the cheap token test
	 * below, because none of those tokens ("bst", "ovt", "cfg", ...) ever
	 * appears in a machine-model name. */
	if (bst_vm_hiding_enabled && bst_bluestacks_file(bst_basename(path))) {
		if (unlikely(bst_hide_log))
			pr_info("hide: ENOENT bluestacks %s (uid %u)\n", path,
				current_uid().val);
		return -ENOENT;
	}

	if (unlikely(bst_vm_path_hidden(path))) {
		if (unlikely(bst_hide_log))
			pr_info("hide: ENOENT vm %s (uid %u)\n", path,
				current_uid().val);
		return -ENOENT;
	}

	/* Cheap rejection first: a path that carries none of these bytes
	 * cannot match anything in the tables.  ("prop" rather than ".propfile"
	 * so that /data/.bluestacks.prop is not filtered out here; "ovt" and
	 * "cfg" cover the files this layer renamed or relocated itself, which
	 * by construction no longer carry a BlueStacks token.) */
	if (likely(!strstr(path, "bst") && !strstr(path, "prop") &&
		   !strstr(path, "idc") && !strstr(path, "ovt") &&
		   !strstr(path, "cfg") && strncmp(path, "/boot/", 6) != 0))
		return orig(regs);

	if (likely(!bst_path_hidden(path)))
		return orig(regs);

	if (unlikely(bst_hide_log))
		pr_info("hide: ENOENT %s (uid %u)\n", path, current_uid().val);

	return -ENOENT;
}

/*
 * L3 SELinux masquerade, part 1: the BlueStacks kernel makes open("/sys/fs/
 * selinux/enforce") return -ENOENT for application uids (stat succeeds, only
 * open lies - a deliberate "pretend selinuxfs does not exist" that no real
 * device exhibits, where every uid reads "1").  Serve our own one-byte file
 * instead: allocate an fd, open the stand-in in kernel space and install it -
 * no user memory is touched, and stat(path) keeps reporting the real inode so
 * the two views stay consistent with a real enforcing device.
 */
#define BST_ENFORCE_PATH	"/sys/fs/selinux/enforce"
#define BST_ENFORCE_STANDIN	"/second_stage_resources/.cfg/enforce"

static long bst_maybe_enforce_redirect(const char __user *uname,
				       const struct pt_regs *regs)
{
	char path[BST_PATH_MAX];
	long fd, flags;
	struct file *f;

	if (likely(!bst_hide_enabled) || likely(bst_uid_trusted()) || !uname)
		return -1;

	memset(path, 0, sizeof(path));
	if (strncpy_from_user_nofault(path, uname, sizeof(path)) < 0)
		return -1;

	if (unlikely(strcmp(path, BST_ENFORCE_PATH) != 0))
		return -1;

	fd = get_unused_fd_flags(PT_REGS_PARM3(regs));
	if (fd < 0)
		return -1;

	flags = PT_REGS_PARM3(regs);
	f = filp_open(BST_ENFORCE_STANDIN, flags & O_ACCMODE, 0644);
	if (IS_ERR(f)) {
		put_unused_fd(fd);
		return -1;
	}
	fd_install(fd, f);
	return fd;
}

static syscall_fn_t bst_orig_openat;
static long bst_sys_openat(const struct pt_regs *regs)
{
	long fd = bst_maybe_enforce_redirect(
		(const char __user *)PT_REGS_PARM2(regs), regs);

	if (fd >= 0)
		return fd;
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

static bool bst_dirname_hidden(const char *name, unsigned int room,
			       const char *dirpath)
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
	if (bst_vm_hiding_enabled && bst_bluestacks_file(tmp))
		return true;
	/* Inside sysfs/devtmpfs the machine-model names are hidden too; the
	 * directory is known here, so no path walk is needed. */
	if (bst_vm_hiding_enabled && dirpath && bst_vm_name_hidden(tmp))
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
static long bst_filter_dirents(char *buf, long len, const char *dirpath)
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

		if (bst_dirname_hidden(de->d_name, reclen - hdr, dirpath)) {
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
				       unsigned int count, const char *dirpath)
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

		filtered = bst_filter_dirents(kbuf, ret, dirpath);
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
	char *dirbuf = NULL;
	struct file *file;
	const char *dirpath = NULL;
	long ret;

	if (likely(!bst_hide_enabled) || likely(bst_uid_trusted()))
		return bst_orig_getdents64(regs);

	/* The machine-model names are only stripped inside sysfs and devtmpfs,
	 * so the directory path is resolved once here instead of being walked
	 * for every entry.  d_path() needs the vfsmount path, hence the fget. */
	file = fget((unsigned int)PT_REGS_SYSCALL_PARM1(regs));
	if (file) {
		unsigned long magic = file->f_path.mnt->mnt_sb->s_magic;
		bool kernel_fs = magic == SYSFS_MAGIC || magic == DEVTMPFS_MAGIC;

		/* Android mounts a tmpfs over /dev, so the node names a
		 * devtmpfs back end would have filtered live in a tmpfs here.
		 * Only /dev itself is treated that way: the rest of the
		 * system's tmpfs directories have nothing of ours in them. */
		if (kernel_fs || magic == TMPFS_MAGIC) {
			dirbuf = kmalloc(PATH_MAX, GFP_KERNEL);
			if (dirbuf) {
				char *p = d_path(&file->f_path, dirbuf, PATH_MAX);

				if (!IS_ERR(p) &&
				    (kernel_fs || !strcmp(p, "/dev")))
					dirpath = p;
			}
		}
		fput(file);
	}

	ret = bst_guard_dirents(bst_orig_getdents64, regs,
				(unsigned int)PT_REGS_PARM3(regs), dirpath);
	kfree(dirbuf);
	return ret;
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

/* ------------------------------------------------------------------ */
/* L4: the selinuxfs status page                                       */
/* ------------------------------------------------------------------ */

/*
 * /sys/fs/selinux/status is not text - it is the 20 byte
 * struct selinux_kernel_status { version, sequence, enforcing, policyload,
 * deny_unknown } mapped read only by libselinux (selinux_status_open).  This
 * guest's kernel is genuinely permissive, so the page reports enforcing 0
 * while the enforce file this layer serves to application uids says "1".
 * A detector that reads both - or that compares the mmap page against
 * getenforce() - sees "direct syscall and libc views disagree", which is
 * exactly the second half of the Miscellaneous Check family.  Serve a
 * self-consistent page to application uids, on both the read and the mmap
 * path (libselinux prefers mmap and would bypass a read-only rewrite).
 */
struct bst_selinux_status {
	__u32 version;
	__u32 sequence;
	__u32 enforcing;
	__u32 policyload;
	__u32 deny_unknown;
};

static const struct bst_selinux_status bst_selinux_fake = {
	.version = 1,
	.sequence = 2,
	.enforcing = 1,
	.policyload = 1,
	.deny_unknown = 1,
};

static bool bst_selinux_status_file(const struct file *file)
{
	return file && file->f_path.mnt->mnt_sb->s_magic == SELINUX_MAGIC &&
	       !strcmp(file->f_path.dentry->d_name.name, "status");
}

static long bst_serve_selinux_status(struct file *file, char __user *ubuf,
				     size_t count)
{
	loff_t pos = file->f_pos;

	if (pos < 0)
		return -EINVAL;
	if ((size_t)pos >= sizeof(bst_selinux_fake))
		return 0;
	if (count > sizeof(bst_selinux_fake) - (size_t)pos)
		count = sizeof(bst_selinux_fake) - (size_t)pos;
	if (copy_to_user(ubuf, (const char *)&bst_selinux_fake + pos, count))
		return -EFAULT;

	file->f_pos = pos + (loff_t)count;
	return (long)count;
}

/*
 * The mmap form: selinux_status_open() maps the page and then polls the
 * sequence field.  An anonymous page pre-filled with the same five words is
 * indistinguishable to the reader.  The mapping is left writable - the
 * original is PROT_READ, but nothing reads the protection back, and writing
 * into it only changes the detector's own private copy.
 */
static long bst_mmap_selinux_status(unsigned long len)
{
	unsigned long size, ret;
	void __user *page;

	if (!len || len > (unsigned long)BST_PATH_MAX * 64)
		return -EINVAL;

	size = PAGE_ALIGN(len);
	ret = vm_mmap(NULL, 0, size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, 0);
	if (IS_ERR_VALUE(ret))
		return (long)ret;

	page = (void __user *)ret;
	if (copy_to_user(page, &bst_selinux_fake, sizeof(bst_selinux_fake))) {
		vm_munmap(ret, size);
		return -EFAULT;
	}

	return (long)ret;
}

static syscall_fn_t bst_orig_mmap;
static long bst_sys_mmap(const struct pt_regs *regs)
{
	unsigned long len = (unsigned long)PT_REGS_PARM2(regs);
	unsigned long off = (unsigned long)PT_REGS_PARM6(regs);
	int flags = (int)PT_REGS_SYSCALL_PARM4(regs);
	struct file *file;

	if (likely(!bst_hide_enabled) || likely(bst_uid_trusted()))
		return bst_orig_mmap(regs);

	/* MAP_FIXED callers want a particular address; do not second guess. */
	if (off || (flags & MAP_FIXED))
		return bst_orig_mmap(regs);

	file = fget((unsigned int)(int)PT_REGS_PARM5(regs));
	if (!file)
		return bst_orig_mmap(regs);

	if (bst_selinux_status_file(file)) {
		long ret;

		if (unlikely(bst_trace_enabled))
			pr_info("trace: app mmap selinux status (uid %u)\n",
				current_uid().val);
		ret = bst_mmap_selinux_status(len);
		fput(file);
		if (ret != -EINVAL)
			return ret;
	}

	fput(file);
	return bst_orig_mmap(regs);
}

static syscall_fn_t bst_orig_read;
static DEFINE_MUTEX(bst_mount_lock);
static long bst_serve_mounts(struct file *file, char __user *ubuf, size_t count);
static long bst_sys_read(const struct pt_regs *regs)
{
	unsigned int fd = PT_REGS_SYSCALL_PARM1(regs);
	char __user *ubuf = (char __user *)PT_REGS_PARM2(regs);
	size_t count = (size_t)PT_REGS_PARM3(regs);
	const char *name;
	struct file *file;
	long ret;

	if (likely(!bst_hide_enabled) || !ubuf || !count)
		return bst_orig_read(regs);

	rcu_read_lock();
	file = fget(fd);
	rcu_read_unlock();
	if (!file)
		return bst_orig_read(regs);

	/* L4: the binary status page, before the procfs branch - selinuxfs. */
	if (bst_selinux_status_file(file)) {
		if (!bst_uid_trusted()) {
			ret = bst_serve_selinux_status(file, ubuf, count);
			fput(file);
			return ret;
		}
		goto plain;
	}

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
	/* cpuinfo and version are served to every uid: a detection SDK that
	 * succeeded in asking for root through the su interface would otherwise
	 * read the real (Apple) topology.  The mount and status rewrites stay
	 * confined to application uids, where the detection surface lives, so
	 * that root-level tooling keeps seeing the actual mount table. */
	if (bst_uid_trusted())
		goto plain;

	if (!strcmp(name, "mountinfo") || !strcmp(name, "mounts")) {
		mutex_lock(&bst_mount_lock);
		ret = bst_serve_mounts(file, ubuf, count);
		mutex_unlock(&bst_mount_lock);
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
	/* L3 SELinux masquerade, part 2: every task on this guest wears the
	 * KernelSU domain (u:r:ksu:s0) because the kernel-side domain switch
	 * never happened - a real device shows u:r:untrustedapp:s0:c512,c768
	 * for application processes, and /proc/self/attr/current is a standard
	 * detection surface (ACE D-list).  Serve the stock context string for
	 * application uids; root, system and shell keep seeing the truth. */
	if (!strcmp(name, "current")) {
		const char *parent = file->f_path.dentry->d_parent->d_name.name;

		if (!strcmp(parent, "attr")) {
			static const char bst_app_ctx[] =
				"u:r:untrustedapp:s0:c512,c768";

			ret = bst_serve_text(file, ubuf, count, bst_app_ctx,
					     sizeof(bst_app_ctx) - 1);
			fput(file);
			return ret;
		}
	}

plain:
	fput(file);
	return bst_orig_read(regs);
}

/*
 * /proc/<pid>/mountinfo and /proc/<pid>/mounts quote the source of every bind
 * mount in their root field, so the six mounts this layer installs would name
 * /second_stage_resources/.cfg and the bst binaries outright.  The whole file
 * is slurped through the file operations (not the syscall under test), the
 * lines that name our layer are dropped, and the filtered copy is served from
 * the caller's file position.  The pseudo files are a few kilobytes and the
 * content does not change between reads, so re-slurping per call keeps the
 * position mapping stable.
 */
static const char *const bst_mount_marks[] = {
	"ovt", "bst", "second_stage_resources", "bprop", "propfile",
	"bluestacks", ".cfg",
};

static char bst_mount_raw[65536];
static char bst_mount_out[65536];

static bool bst_contains(const char *hay, size_t len, const char *needle)
{
	size_t nlen = strlen(needle);
	size_t i;

	if (!nlen || nlen > len)
		return false;

	for (i = 0; i + nlen <= len; i++) {
		if (!memcmp(hay + i, needle, nlen))
			return true;
	}
	return false;
}

static long bst_serve_mounts(struct file *file, char __user *ubuf, size_t count)
{
	loff_t pos = 0;
	loff_t want = file->f_pos;
	size_t total = 0, out = 0, line = 0, i;
	long n, served;
	int m;

	while (total + 4096 < sizeof(bst_mount_raw)) {
		n = kernel_read(file, bst_mount_raw + total,
				sizeof(bst_mount_raw) - total - 4096, &pos);
		if (n <= 0)
			break;
		total += (size_t)n;
	}

	for (i = 0; i < total; i++) {
		size_t len;
		bool drop = false;

		if (bst_mount_raw[i] != '\n')
			continue;

		len = i - line;
		for (m = 0; m < (int)ARRAY_SIZE(bst_mount_marks); m++) {
			if (bst_contains(bst_mount_raw + line, len, bst_mount_marks[m])) {
				drop = true;
				break;
			}
		}
		if (!drop && out + len + 1 <= sizeof(bst_mount_out)) {
			memcpy(bst_mount_out + out, bst_mount_raw + line, len);
			bst_mount_out[out + len] = '\n';
			out += len + 1;
		}
		line = i + 1;
	}

	if (want < 0 || (size_t)want >= out)
		return 0;

	served = (long)(out - (size_t)want);
	if ((size_t)served > count)
		served = (long)count;

	if (copy_to_user(ubuf, bst_mount_out + want, served))
		return -EFAULT;

	file->f_pos = want + served;
	return served;
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
/* self-kill guard                                                     */
/* ------------------------------------------------------------------ */

/*
 * The Chunqiu native detector ends a failed verdict by killing its own
 * process with SIGKILL - no tombstone, no log, the app just vanishes.  A
 * normal application never deliberately SIGKILLs itself, so for application
 * uids we drop exactly that one signal and let the run reach its UI, where
 * the individual findings stay readable.
 *
 * Scope is deliberately narrow: SIGKILL only, caller uid >= 10000, target
 * must be the caller's own thread group (pid == getpid(), which is what the
 * detector stores and re-uses, or pid <= 0, the killpg(2) form aimed at its
 * own group).  init, system_server, HALs, and every system uid are untouched.
 */

/* ------------------------------------------------------------------ */
/* guard forensics: the last few paths an app process touched          */
/* ------------------------------------------------------------------ */

/*
 * The detector decides to SIGKILL itself about fifteen seconds in, on this
 * guest, whatever the mask is doing - the masking layers are not what it
 * dislikes.  When the guard drops that signal it dumps the tail of this
 * ring, so the paths that led to the decision are in dmesg instead of being
 * guessed at.  Entries are only recorded for application uids.
 */
#define BST_RING_MAX	256
#define BST_RING_PATH	56

struct bst_ring_ent {
	u32 tid;
	u16 nr;
	u16 len;
	s64 a0;
	s64 a1;
	char path[BST_RING_PATH];
};

static struct bst_ring_ent bst_ring[BST_RING_MAX];
static unsigned int bst_ring_pos;
static DEFINE_SPINLOCK(bst_ring_lock);

static void bst_ring_add(u16 nr, s64 a0, s64 a1, const char *path)
{
	unsigned long flags;
	struct bst_ring_ent *e;
	size_t n = 0;

	if (!bst_trace_enabled)
		return;

	spin_lock_irqsave(&bst_ring_lock, flags);
	e = &bst_ring[bst_ring_pos];
	bst_ring_pos = (bst_ring_pos + 1) % BST_RING_MAX;
	e->tid = current->pid;
	e->nr = nr;
	e->a0 = a0;
	e->a1 = a1;
	if (path) {
		n = strlen(path);
		if (n >= BST_RING_PATH) {
			path += n - (BST_RING_PATH - 1);
			n = BST_RING_PATH - 1;
		}
		memcpy(e->path, path, n);
	}
	e->path[n] = '\0';
	e->len = (u16)n;
	spin_unlock_irqrestore(&bst_ring_lock, flags);
}

static void bst_ring_dump(void)
{
	unsigned long flags;
	unsigned int i, idx;

	spin_lock_irqsave(&bst_ring_lock, flags);
	for (i = 0; i < 128; i++) {
		const struct bst_ring_ent *e;

		idx = (bst_ring_pos + BST_RING_MAX - 128 + i) % BST_RING_MAX;
		e = &bst_ring[idx];
		if (!e->nr)
			continue;
		pr_info("guard-dump: tid %u nr %u a0 %lld a1 %lld %s\n",
			e->tid, e->nr, (long long)e->a0, (long long)e->a1,
			e->path);
	}
	spin_unlock_irqrestore(&bst_ring_lock, flags);
}

static bool bst_killguard_enabled __read_mostly = true;
module_param_named(bst_killguard, bst_killguard_enabled, bool, 0644);

static atomic_t bst_killguard_hits = ATOMIC_INIT(0);

static noinline bool bst_killguard_self(pid_t pid)
{
	pid_t tgid = task_tgid_vnr(current);

	return pid == tgid || pid == 0 || pid == -tgid;
}

static noinline bool bst_killguard_drop(int sig, pid_t pid)
{
	int hits;

	if (likely(sig != SIGKILL) || likely(!bst_killguard_enabled) ||
	    likely(bst_uid_trusted()) || !bst_killguard_self(pid))
		return false;

	bst_ring_add(__NR_kill, (s64)pid, (s64)sig, NULL);

	hits = atomic_inc_return(&bst_killguard_hits);
	if (hits <= 8 || (hits % 64) == 0)
		pr_info("bst_hide: dropped self SIGKILL from %s (uid %u, hit %d)\n",
			current->comm, current_uid().val, hits);
	if (hits <= 4)
		bst_ring_dump();
	return true;
}

static syscall_fn_t bst_orig_kill;
static long bst_sys_kill(const struct pt_regs *regs)
{
	if (bst_killguard_drop((int)PT_REGS_PARM2(regs),
			       (pid_t)PT_REGS_PARM1(regs)))
		return 0;

	return bst_orig_kill(regs);
}

static syscall_fn_t bst_orig_tgkill;
static long bst_sys_tgkill(const struct pt_regs *regs)
{
	if (bst_killguard_drop((int)PT_REGS_PARM3(regs),
			       (pid_t)PT_REGS_PARM1(regs)))
		return 0;

	return bst_orig_tgkill(regs);
}

/*
 * prctl(PR_GET_SECCOMP) reports 0 on this guest for every process: the image
 * runs SELinux disabled, so zygote never installs a seccomp filter and ART
 * says so out loud ("seccomp disabled by setenforce 0").  /proc/PID/status is
 * rewritten to claim a filter, and this closes the other door to the same
 * fact.
 */
#define BST_PR_GET_SECCOMP	21
#define BST_SECCOMP_FILTER	2

static syscall_fn_t bst_orig_prctl;

static long bst_sys_prctl(const struct pt_regs *regs)
{
	if (likely(!bst_hide_enabled) || likely(bst_uid_trusted()))
		return bst_orig_prctl(regs);

	if ((int)PT_REGS_SYSCALL_PARM1(regs) == BST_PR_GET_SECCOMP) {
		bst_ring_add(__NR_prctl, BST_PR_GET_SECCOMP, 0, NULL);
		return BST_SECCOMP_FILTER;
	}

	return bst_orig_prctl(regs);
}


/* ------------------------------------------------------------------ */
/* run-time switches: /proc/ovtcfg                                     */
/* ------------------------------------------------------------------ */

/*
 * Reading and writing this file is root only.  It exists so the layers that
 * are guesses (machine-model hiding, the selinux status page) can be turned
 * off and on again while a detector is running, which is the only way to
 * tell a layer that helps from one that merely looks convincing.
 */
static int bst_cfg_show(struct seq_file *m, void *v)
{
	seq_printf(m,
		   "hide %d\nvm %d\nselinux %d\ntrace %d\nlog %d\nkillguard %d\nhits %d\n",
		   bst_hide_enabled, bst_vm_hiding_enabled,
		   bst_selinux_fake_enabled, bst_trace_enabled,
		   bst_hide_log, bst_killguard_enabled,
		   atomic_read(&bst_trace_hits));
	return 0;
}

static int bst_cfg_open(struct inode *inode, struct file *file)
{
	return single_open(file, bst_cfg_show, NULL);
}

static ssize_t bst_cfg_write(struct file *file, const char __user *ubuf,
			     size_t count, loff_t *ppos)
{
	char buf[64];
	char key[16];
	int val;
	int rc;

	if (current_uid().val != 0)
		return -EPERM;
	if (!count || count >= sizeof(buf))
		return -EINVAL;
	if (copy_from_user(buf, ubuf, count))
		return -EFAULT;
	buf[count] = '\0';
	rc = sscanf(buf, "%15s %d", key, &val);
	if (rc < 1)
		return -EINVAL;
	if (!strcmp(key, "dump")) {
		bst_ring_dump();
		return count;
	}
	if (rc != 2)
		return -EINVAL;

	if (!strcmp(key, "hide"))
		bst_hide_enabled = val;
	else if (!strcmp(key, "vm"))
		bst_vm_hiding_enabled = val;
	else if (!strcmp(key, "selinux"))
		bst_selinux_fake_enabled = val;
	else if (!strcmp(key, "trace")) {
		bst_trace_enabled = val;
		if (val)
			atomic_set(&bst_trace_hits, 0);
	} else if (!strcmp(key, "log"))
		bst_hide_log = val;
	else if (!strcmp(key, "killguard"))
		bst_killguard_enabled = val;
	else
		return -EINVAL;

	return count;
}

static const struct proc_ops bst_cfg_procs = {
	.proc_open = bst_cfg_open,
	.proc_read = seq_read,
	.proc_write = bst_cfg_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

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
	/* Kill guard: keeps a self-killing detector alive long enough to show
	 * its verdict.  Same table, same mechanism, no extra footprint. */
	ksu_syscall_table_hook(__NR_kill, bst_sys_kill, &bst_orig_kill);
	ksu_syscall_table_hook(__NR_tgkill, bst_sys_tgkill, &bst_orig_tgkill);
	ksu_syscall_table_hook(__NR_prctl, bst_sys_prctl, &bst_orig_prctl);
	/* mmap only adjudicates the selinuxfs status page for application
	 * uids; every other mapping (and every other uid) passes straight
	 * through to the original entry. */
	ksu_syscall_table_hook(__NR_mmap, bst_sys_mmap, &bst_orig_mmap);

	bst_build_cpuinfo();
	bst_rewrite_utsname();

	if (!proc_create("ovtcfg", 0600, NULL, &bst_cfg_procs))
		pr_warn("bst_hide: /proc/ovtcfg unavailable\n");

	pr_info("bst_hide: layer 2 path adjudication + proc text + kill guard installed\n");
}
