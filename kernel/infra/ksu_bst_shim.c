// SPDX-License-Identifier: GPL-2.0
/*
 * ksu_bst_shim.c - global definitions for kernel symbols present in the
 * target kernel but not exported.  Each wrapper carries the same name as the
 * kernel symbol, so module-internal references bind here at link time; the
 * real address is resolved via kallsyms on first use.
 *
 * Kernel headers declaring these symbols are included FIRST so that
 * attribute-carrying prototypes precede our definitions.
 */
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/kallsyms.h>
#include <linux/task_work.h>
#include <linux/seccomp.h>
#include <linux/fs_struct.h>
#include <linux/cred.h>
#include <linux/uidgid.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/proc_ns.h>
#include <linux/tracepoint.h>
#include <linux/security.h>
#include <linux/utsname.h>
#include <linux/pid.h>
#include <asm/fixmap.h>
#include <asm/cacheflush.h>
#include <avc.h>

#include "infra/symbol_resolver.h"
#include "infra/ksu_bst_shim.h"
#include "klog.h"

static void *bst_sym(const char *name, void **cache, bool *tried)
{
	if (!*cache && !*tried) {
		*tried = true;
		*cache = (void *)find_kernel_symbol_exact(name);
		if (!*cache)
			pr_warn_once("KernelSU: bst shim: %s not found\n", name);
	}
	return *cache;
}

#define BST_DECL(ret, name, ...)                                               \
	static void *p_##name;                                                 \
	static bool t_##name;                                                  \
	ret name(__VA_ARGS__)

#define BST_RESOLVE(name)                                                      \
	((void)bst_sym(#name, &p_##name, &t_##name))

#define BST_FN(name)                                                           \
	(__typeof__(name) *)bst_sym(#name, &p_##name, &t_##name)

/* ============ fs / ns / cred ============ */
BST_DECL(int, path_umount, struct path *path, int flags)
{
	int (*fn)(struct path *, int) = BST_FN(path_umount);
	return fn ? fn(path, flags) : -ENOENT;
}
BST_DECL(int, path_mount, const char *dev_name, struct path *path,
	 const char *type_page, unsigned long flags, void *data_page)
{
	int (*fn)(const char *, struct path *, const char *, unsigned long,
		  void *) = BST_FN(path_mount);
	return fn ? fn(dev_name, path, type_page, flags, data_page) : -ENOENT;
}
BST_DECL(int, ksys_unshare, unsigned long unshare_flags)
{
	int (*fn)(unsigned long) = BST_FN(ksys_unshare);
	return fn ? fn(unshare_flags) : -ENOENT;
}
BST_DECL(void, set_fs_pwd, struct fs_struct *fs, const struct path *path)
{
	void (*fn)(struct fs_struct *, const struct path *) = BST_FN(set_fs_pwd);
	if (fn)
		fn(fs, path);
}
BST_DECL(int, ns_get_path, struct path *path, struct task_struct *task,
	 const struct proc_ns_operations *ns_ops)
{
	int (*fn)(struct path *, struct task_struct *,
		  const struct proc_ns_operations *) = BST_FN(ns_get_path);
	return fn ? fn(path, task, ns_ops) : -ENOENT;
}
BST_DECL(void, change_pid, struct task_struct *task, int type, struct pid *pid)
{
	void (*fn)(struct task_struct *, enum pid_type, struct pid *) =
		BST_FN(change_pid);
	if (fn)
		fn(task, (enum pid_type)type, pid);
}
BST_DECL(bool, current_is_single_threaded, void)
{
	bool (*fn)(void) = BST_FN(current_is_single_threaded);
	return fn ? fn() : false;
}
BST_DECL(int, task_work_add, struct task_struct *task,
	 struct callback_head *twork, int mode)
{
	int (*fn)(struct task_struct *, struct callback_head *,
		  enum task_work_notify_mode) = BST_FN(task_work_add);
	return fn ? fn(task, twork, (enum task_work_notify_mode)mode) : -ENOENT;
}
BST_DECL(struct user_struct *, alloc_uid, kuid_t uid)
{
	struct user_struct *(*fn)(kuid_t) = BST_FN(alloc_uid);
	return fn ? fn(uid) : NULL;
}
BST_DECL(int, set_cred_ucounts, struct cred *cred)
{
	int (*fn)(struct cred *) = BST_FN(set_cred_ucounts);
	return fn ? fn(cred) : -ENOENT;
}
BST_DECL(void, seccomp_filter_release, struct task_struct *tsk)
{
	void (*fn)(struct task_struct *) = BST_FN(seccomp_filter_release);
	if (fn)
		fn(tsk);
}
BST_DECL(void, ext4_unregister_sysfs, struct super_block *sb)
{
	void (*fn)(struct super_block *) = BST_FN(ext4_unregister_sysfs);
	if (fn)
		fn(sb);
}

/* ============ kallsyms ============ */
BST_DECL(unsigned long, kallsyms_lookup, unsigned long addr,
	 unsigned long *symbolsize, unsigned long *offset, char **modname,
	 char *namebuf)
{
	unsigned long (*fn)(unsigned long, unsigned long *, unsigned long *,
			    char **, char *) = BST_FN(kallsyms_lookup);
	return fn ? fn(addr, symbolsize, offset, modname, namebuf) : 0;
}
BST_DECL(int, kallsyms_lookup_size_offset, unsigned long addr,
	 unsigned long *symbolsize, unsigned long *offset)
{
	int (*fn)(unsigned long, unsigned long *, unsigned long *) =
		BST_FN(kallsyms_lookup_size_offset);
	return fn ? fn(addr, symbolsize, offset) : 0;
}
/* Bootstrap: kallsyms_lookup_name itself is resolved from the boot stage. */
unsigned long kallsyms_lookup_name(const char *name)
{
	return ksu_bst_kln(name);
}

/* ============ syscall wrappers ============ */
BST_DECL(long, __arm64_sys_close, const struct pt_regs *regs)
{
	long (*fn)(const struct pt_regs *) = BST_FN(__arm64_sys_close);
	return fn ? fn(regs) : -ENOENT;
}
BST_DECL(long, __arm64_sys_setns, const struct pt_regs *regs)
{
	long (*fn)(const struct pt_regs *) = BST_FN(__arm64_sys_setns);
	return fn ? fn(regs) : -ENOENT;
}

/* ============ arch / mem ============ */
BST_DECL(void, __set_fixmap, int idx, phys_addr_t phys, pgprot_t flags)
{
	void (*fn)(enum fixed_addresses, phys_addr_t, pgprot_t) =
		BST_FN(__set_fixmap);
	if (fn)
		fn((enum fixed_addresses)idx, phys, flags);
}
BST_DECL(long, copy_to_kernel_nofault, void *dst, const void *src, size_t size)
{
	long (*fn)(void *, const void *, size_t) = BST_FN(copy_to_kernel_nofault);
	return fn ? fn(dst, src, size) : -ENOENT;
}
BST_DECL(long, strncpy_from_user_nofault, char *dst, const void __user *src,
	 long count)
{
	long (*fn)(char *, const void __user *, long) =
		BST_FN(strncpy_from_user_nofault);
	return fn ? fn(dst, src, count) : -ENOENT;
}
BST_DECL(void, dcache_clean_inval_poc, unsigned long start, unsigned long end)
{
	void (*fn)(unsigned long, unsigned long) = BST_FN(dcache_clean_inval_poc);
	if (fn)
		fn(start, end);
}

/* ============ kprobes: absent in the target kernel ============ */
int register_kprobe(struct kprobe *p)
{
	(void)p;
	return -ENOTSUPP;
}
void unregister_kprobe(struct kprobe *p)
{
	(void)p;
}
int register_kretprobe(struct kretprobe *rp)
{
	(void)rp;
	return -ENOTSUPP;
}
void unregister_kretprobe(struct kretprobe *rp)
{
	(void)rp;
}

/* ============ SELinux ============ */
BST_DECL(int, avc_has_perm, struct selinux_state *state, u32 ssid, u32 tsid,
	 u16 tclass, u32 requested, struct common_audit_data *auditdata)
{
	int (*fn)(struct selinux_state *, u32, u32, u16, u32,
		  struct common_audit_data *) = BST_FN(avc_has_perm);
	return fn ? fn(state, ssid, tsid, tclass, requested, auditdata) : -ENOENT;
}
BST_DECL(int, avc_ss_reset, struct selinux_avc *avc, u32 seqno)
{
	int (*fn)(struct selinux_avc *, u32) = BST_FN(avc_ss_reset);
	return fn ? fn(avc, seqno) : -ENOENT;
}
BST_DECL(void, selnl_notify_policyload, u32 seqno)
{
	void (*fn)(u32) = BST_FN(selnl_notify_policyload);
	if (fn)
		fn(seqno);
}
BST_DECL(void, selinux_status_update_policyload, struct selinux_state *state,
	 int seqno)
{
	void (*fn)(struct selinux_state *, int) =
		BST_FN(selinux_status_update_policyload);
	if (fn)
		fn(state, seqno);
}
BST_DECL(int, security_bounded_transition, struct selinux_state *state,
	 u32 old_sid, u32 new_sid)
{
	int (*fn)(struct selinux_state *, u32, u32) =
		BST_FN(security_bounded_transition);
	return fn ? fn(state, old_sid, new_sid) : -ENOENT;
}
BST_DECL(int, security_inode_init_security_anon, struct inode *inode,
	 const struct qstr *name, const struct inode *context_inode)
{
	int (*fn)(struct inode *, const struct qstr *, const struct inode *) =
		BST_FN(security_inode_init_security_anon);
	return fn ? fn(inode, name, context_inode) : -ENOENT;
}
BST_DECL(int, mls_context_to_sid, struct policydb *p, char oldc,
	 char *scontext, struct context *context, struct sidtab *s, u32 def_sid)
{
	int (*fn)(struct policydb *, char, char *, struct context *, struct sidtab *,
		  u32) = BST_FN(mls_context_to_sid);
	return fn ? fn(p, oldc, scontext, context, s, def_sid) : -ENOENT;
}
BST_DECL(int, policydb_context_isvalid, struct policydb *p, struct context *c)
{
	int (*fn)(struct policydb *, struct context *) =
		BST_FN(policydb_context_isvalid);
	return fn ? fn(p, c) : -ENOENT;
}
BST_DECL(void, policydb_destroy, struct policydb *p)
{
	void (*fn)(struct policydb *) = BST_FN(policydb_destroy);
	if (fn)
		fn(p);
}
BST_DECL(int, policydb_load_isids, struct policydb *p, struct sidtab *s)
{
	int (*fn)(struct policydb *, struct sidtab *) = BST_FN(policydb_load_isids);
	return fn ? fn(p, s) : -ENOENT;
}
BST_DECL(struct filename_trans_datum *, policydb_filenametr_search,
	 struct policydb *p, struct filename_trans_key *key)
{
	struct filename_trans_datum *(*fn)(struct policydb *,
					   struct filename_trans_key *) =
		BST_FN(policydb_filenametr_search);
	return fn ? fn(p, key) : NULL;
}
BST_DECL(int, policydb_write, struct policydb *p, void *fp)
{
	int (*fn)(struct policydb *, void *) = BST_FN(policydb_write);
	return fn ? fn(p, fp) : -ENOENT;
}
BST_DECL(int, sidtab_context_to_sid, struct sidtab *s, struct context *context,
	 u32 *sid)
{
	int (*fn)(struct sidtab *, struct context *, u32 *) =
		BST_FN(sidtab_context_to_sid);
	return fn ? fn(s, context, sid) : -ENOENT;
}
BST_DECL(void, sidtab_destroy, struct sidtab *s)
{
	void (*fn)(struct sidtab *) = BST_FN(sidtab_destroy);
	if (fn)
		fn(s);
}
BST_DECL(int, avtab_alloc, struct avtab *h, u32 nrules)
{
	int (*fn)(struct avtab *, u32) = BST_FN(avtab_alloc);
	return fn ? fn(h, nrules) : -ENOENT;
}
BST_DECL(void, avtab_destroy, struct avtab *h)
{
	void (*fn)(struct avtab *) = BST_FN(avtab_destroy);
	if (fn)
		fn(h);
}
BST_DECL(struct avtab_node *, avtab_insert_nonunique, struct avtab *h,
	 const struct avtab_key *key, const struct avtab_datum *datum)
{
	struct avtab_node *(*fn)(struct avtab *, const struct avtab_key *,
				 const struct avtab_datum *) =
		BST_FN(avtab_insert_nonunique);
	return fn ? fn(h, key, datum) : NULL;
}
BST_DECL(struct avtab_node *, avtab_search_node, struct avtab *h,
	 const struct avtab_key *key)
{
	struct avtab_node *(*fn)(struct avtab *, const struct avtab_key *) =
		BST_FN(avtab_search_node);
	return fn ? fn(h, key) : NULL;
}
BST_DECL(struct avtab_node *, avtab_search_node_next, struct avtab_node *node,
	 int specified)
{
	struct avtab_node *(*fn)(struct avtab_node *, int) =
		BST_FN(avtab_search_node_next);
	return fn ? fn(node, specified) : NULL;
}
BST_DECL(int, __hashtab_insert, struct hashtab *h, struct hashtab_node **dst,
	 void *key, void *datum)
{
	int (*fn)(struct hashtab *, struct hashtab_node **, void *, void *) =
		BST_FN(__hashtab_insert);
	return fn ? fn(h, dst, key, datum) : -ENOENT;
}
BST_DECL(int, symtab_insert, struct symtab *s, char *name, void *datum)
{
	int (*fn)(struct symtab *, char *, void *) = BST_FN(symtab_insert);
	return fn ? fn(s, name, datum) : -ENOENT;
}
BST_DECL(void *, symtab_search, struct symtab *s, const char *name)
{
	void *(*fn)(struct symtab *, const char *) = BST_FN(symtab_search);
	return fn ? fn(s, name) : NULL;
}
BST_DECL(void, ebitmap_destroy, struct ebitmap *e)
{
	void (*fn)(struct ebitmap *) = BST_FN(ebitmap_destroy);
	if (fn)
		fn(e);
}
