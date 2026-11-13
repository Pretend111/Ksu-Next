/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ksu_bst_shim.h - route non-exported kernel symbols through kallsyms
 * for KernelSU-Next LKM on non-GKI kernels (BlueStacks Air 5.15.137).
 *
 * Must be included EARLY in each TU, before any kernel header that may
 * expand inline helpers referencing these symbols.  Resolving requires
 * kallsyms_lookup_name, which is provided via the insmod parameter
 * `ksu_bst_kln_addr` set by the initrd boot script (see resolver.c).
 *
 * Kprobe symbols do not exist in this kernel (CONFIG_KPROBES=n): their
 * wrappers return -ENOTSUPP so callers fall back to tracepoint paths.
 */
#ifndef __KSU_BST_SHIM_H
#define __KSU_BST_SHIM_H

#include <linux/version.h>
#include <linux/types.h>
#include <linux/uidgid.h>
#include <asm/fixmap.h>
#include <asm/pgtable-types.h>
#include <linux/errno.h>
#include <asm-generic/errno-base.h>
#include "infra/symbol_resolver.h"
#include "klog.h"

struct mm_struct;
struct selinux_state;
struct selinux_blob_sizes;
struct proc_ns_operations;
struct tracepoint;
struct semaphore;
struct selinux_avc;
struct path;
struct task_struct;
struct pid;
struct cred;
struct user_struct;
struct super_block;
struct pt_regs;
struct inode;
struct qstr;
struct policydb;
struct context;
struct sidtab;
struct avtab;
struct avtab_key;
struct avtab_datum;
struct avtab_node;
struct hashtab;
struct hashtab_node;
struct symtab;
struct ebitmap;
struct filename_trans_key;
struct filename_trans_datum;
struct kprobe;
struct kretprobe;
struct common_audit_data;
struct callback_head;
struct fs_struct;

/* ============ kallsyms_lookup_name bootstrap (insmod param) ============ */
extern unsigned long long ksu_bst_kln_addr;
extern unsigned long (*ksu_bst_kln_fn)(const char *name);

static inline unsigned long ksu_bst_kln(const char *name)
{
	if (unlikely(!ksu_bst_kln_fn))
		return 0;
	return ksu_bst_kln_fn(name);
}

/* ============ generic function shim machinery ============ */
#define KSU_BST_DECL(ret, name, args...)                                       \
	static ret (*ksu_bst_p_##name)(args);                                  \
	static bool ksu_bst_tried_##name;                                      \
	static ret ksu_bst_##name(args)

#define KSU_BST_RESOLVE(name)                                                  \
	do {                                                                   \
		if (!ksu_bst_p_##name && !ksu_bst_tried_##name) {              \
			ksu_bst_tried_##name = true;                           \
			ksu_bst_p_##name = (void *)find_kernel_symbol_exact(#name); \
			if (!ksu_bst_p_##name)                                 \
				pr_warn_once("KernelSU: bst shim: " #name " not found\n"); \
		}                                                              \
	} while (0)

#define KSU_BST_ALIAS(name)                                                    \
	do {                                                                   \
		KSU_BST_RESOLVE(name);                                         \
	} while (0)

/* ============ data symbol getters ============ */
#define KSU_BST_DATA(ctype, name)                                              \
	static void *ksu_bst_a_##name(void)                                    \
	{                                                                      \
		static void *addr;                                             \
		static bool tried;                                             \
		if (!addr && !tried) {                                         \
			tried = true;                                          \
			addr = (void *)find_kernel_symbol_exact(#name);        \
			if (!addr)                                             \
				pr_warn_once("KernelSU: bst shim: " #name " not found\n"); \
		}                                                              \
		return addr;                                                   \
	}                                                                      \
	static ctype *ksu_bst_ptr_##name(void)                                 \
	{                                                                      \
		return (ctype *)ksu_bst_a_##name();                            \
	}

KSU_BST_DATA(struct mm_struct, init_mm)
KSU_BST_DATA(struct selinux_state, selinux_state)
KSU_BST_DATA(struct selinux_blob_sizes, selinux_blob_sizes)
KSU_BST_DATA(struct proc_ns_operations, mntns_operations)
KSU_BST_DATA(struct tracepoint, __tracepoint_sys_enter)
KSU_BST_DATA(struct semaphore, uts_sem)

/*
 * Data symbols are accessed through the getters above at rewritten call
 * sites (a `#define` would also rewrite the kernel headers' extern
 * declarations into invalid syntax).
 */

/* ============ fs / ns / cred ============ */
KSU_BST_DECL(int, path_umount, struct path *path, int flags)
{
	KSU_BST_ALIAS(path_umount);
	return ksu_bst_p_path_umount ? ksu_bst_p_path_umount(path, flags) : -ENOENT;
}
KSU_BST_DECL(int, path_mount, const char *dev_name, struct path *path,
	     const char *type_page, unsigned long flags, void *data_page)
{
	KSU_BST_ALIAS(path_mount);
	return ksu_bst_p_path_mount ?
		       ksu_bst_p_path_mount(dev_name, path, type_page, flags, data_page) :
		       -ENOENT;
}
KSU_BST_DECL(int, ksys_unshare, unsigned long unshare_flags)
{
	KSU_BST_ALIAS(ksys_unshare);
	return ksu_bst_p_ksys_unshare ? ksu_bst_p_ksys_unshare(unshare_flags) : -ENOENT;
}
KSU_BST_DECL(void, set_fs_pwd, struct fs_struct *fs, const struct path *path)
{
	KSU_BST_ALIAS(set_fs_pwd);
	if (ksu_bst_p_set_fs_pwd)
		ksu_bst_p_set_fs_pwd(fs, path);
}
KSU_BST_DECL(int, ns_get_path, struct path *path, struct task_struct *task,
	     const struct proc_ns_operations *ns_ops)
{
	KSU_BST_ALIAS(ns_get_path);
	return ksu_bst_p_ns_get_path ?
		       ksu_bst_p_ns_get_path(path, task, ns_ops) : -ENOENT;
}
KSU_BST_DECL(void, change_pid, struct task_struct *task, int type,
	     struct pid *pid)
{
	KSU_BST_ALIAS(change_pid);
	if (ksu_bst_p_change_pid)
		ksu_bst_p_change_pid(task, type, pid);
}
KSU_BST_DECL(bool, current_is_single_threaded, void)
{
	KSU_BST_ALIAS(current_is_single_threaded);
	return ksu_bst_p_current_is_single_threaded ?
		       ksu_bst_p_current_is_single_threaded() : false;
}
KSU_BST_DECL(int, task_work_add, struct task_struct *task,
	     struct callback_head *twork, int mode)
{
	KSU_BST_ALIAS(task_work_add);
	return ksu_bst_p_task_work_add ?
		       ksu_bst_p_task_work_add(task, twork, mode) : -ENOENT;
}
KSU_BST_DECL(struct user_struct *, alloc_uid, kuid_t uid)
{
	KSU_BST_ALIAS(alloc_uid);
	return ksu_bst_p_alloc_uid ? ksu_bst_p_alloc_uid(uid) : NULL;
}
KSU_BST_DECL(int, set_cred_ucounts, struct cred *cred)
{
	KSU_BST_ALIAS(set_cred_ucounts);
	return ksu_bst_p_set_cred_ucounts ? ksu_bst_p_set_cred_ucounts(cred) : -ENOENT;
}
KSU_BST_DECL(void, seccomp_filter_release, struct task_struct *tsk)
{
	KSU_BST_ALIAS(seccomp_filter_release);
	if (ksu_bst_p_seccomp_filter_release)
		ksu_bst_p_seccomp_filter_release(tsk);
}
KSU_BST_DECL(void, ext4_unregister_sysfs, struct super_block *sb)
{
	KSU_BST_ALIAS(ext4_unregister_sysfs);
	if (ksu_bst_p_ext4_unregister_sysfs)
		ksu_bst_p_ext4_unregister_sysfs(sb);
}

/* ============ kallsyms ============ */
KSU_BST_DECL(unsigned long, kallsyms_lookup, unsigned long addr,
	     unsigned long *symbolsize, unsigned long *offset, char **modname,
	     char *namebuf)
{
	KSU_BST_ALIAS(kallsyms_lookup);
	return ksu_bst_p_kallsyms_lookup ?
		       ksu_bst_p_kallsyms_lookup(addr, symbolsize, offset, modname, namebuf) :
		       0;
}
KSU_BST_DECL(int, kallsyms_lookup_size_offset, unsigned long addr,
	     unsigned long *symbolsize, unsigned long *offset)
{
	KSU_BST_ALIAS(kallsyms_lookup_size_offset);
	return ksu_bst_p_kallsyms_lookup_size_offset ?
		       ksu_bst_p_kallsyms_lookup_size_offset(addr, symbolsize, offset) : 0;
}
/* kallsyms_lookup_name goes through the boot-provided function pointer. */
static unsigned long ksu_bst_kallsyms_lookup_name(const char *name)
{
	return ksu_bst_kln(name);
}

/* ============ syscall wrappers ============ */
KSU_BST_DECL(long, __arm64_sys_close, const struct pt_regs *regs)
{
	KSU_BST_ALIAS(__arm64_sys_close);
	return ksu_bst_p___arm64_sys_close ? ksu_bst_p___arm64_sys_close(regs) : -ENOENT;
}
KSU_BST_DECL(long, __arm64_sys_setns, const struct pt_regs *regs)
{
	KSU_BST_ALIAS(__arm64_sys_setns);
	return ksu_bst_p___arm64_sys_setns ? ksu_bst_p___arm64_sys_setns(regs) : -ENOENT;
}

/* ============ arch / mem ============ */
KSU_BST_DECL(void, __set_fixmap, int idx, phys_addr_t phys, pgprot_t flags)
{
	KSU_BST_ALIAS(__set_fixmap);
	if (ksu_bst_p___set_fixmap)
		ksu_bst_p___set_fixmap(idx, phys, flags);
}
KSU_BST_DECL(long, copy_to_kernel_nofault, void *dst, const void *src,
	     size_t size)
{
	KSU_BST_ALIAS(copy_to_kernel_nofault);
	return ksu_bst_p_copy_to_kernel_nofault ?
		       ksu_bst_p_copy_to_kernel_nofault(dst, src, size) : -ENOENT;
}
KSU_BST_DECL(long, strncpy_from_user_nofault, char *dst, const void __user *src,
	     long count)
{
	KSU_BST_ALIAS(strncpy_from_user_nofault);
	return ksu_bst_p_strncpy_from_user_nofault ?
		       ksu_bst_p_strncpy_from_user_nofault(dst, src, count) : -ENOENT;
}
KSU_BST_DECL(void, dcache_clean_inval_poc, unsigned long start, unsigned long end)
{
	KSU_BST_ALIAS(dcache_clean_inval_poc);
	if (ksu_bst_p_dcache_clean_inval_poc)
		ksu_bst_p_dcache_clean_inval_poc(start, end);
}

/* ============ kprobes: absent in this kernel ============ */
static int ksu_bst_register_kprobe(struct kprobe *p)
{
	(void)p;
	return -ENOTSUPP;
}
static void ksu_bst_unregister_kprobe(struct kprobe *p)
{
	(void)p;
}
static int ksu_bst_register_kretprobe(struct kretprobe *rp)
{
	(void)rp;
	return -ENOTSUPP;
}
static void ksu_bst_unregister_kretprobe(struct kretprobe *rp)
{
	(void)rp;
}

/* ============ SELinux ============ */
KSU_BST_DECL(int, avc_has_perm, struct selinux_state *state, u32 ssid,
	     u32 tsid, u16 tclass, u32 requested,
	     struct common_audit_data *auditdata)
{
	KSU_BST_ALIAS(avc_has_perm);
	return ksu_bst_p_avc_has_perm ?
		       ksu_bst_p_avc_has_perm(state, ssid, tsid, tclass, requested, auditdata) :
		       -ENOENT;
}
KSU_BST_DECL(int, avc_ss_reset, struct selinux_avc *avc, u32 seqno)
{
	KSU_BST_ALIAS(avc_ss_reset);
	return ksu_bst_p_avc_ss_reset ? ksu_bst_p_avc_ss_reset(avc, seqno) : -ENOENT;
}
KSU_BST_DECL(void, selnl_notify_policyload, u32 seqno)
{
	KSU_BST_ALIAS(selnl_notify_policyload);
	if (ksu_bst_p_selnl_notify_policyload)
		ksu_bst_p_selnl_notify_policyload(seqno);
}
KSU_BST_DECL(void, selinux_status_update_policyload, struct selinux_state *state,
	     int seqno)
{
	KSU_BST_ALIAS(selinux_status_update_policyload);
	if (ksu_bst_p_selinux_status_update_policyload)
		ksu_bst_p_selinux_status_update_policyload(state, seqno);
}
KSU_BST_DECL(int, security_bounded_transition, struct selinux_state *state,
	     u32 old_sid, u32 new_sid)
{
	KSU_BST_ALIAS(security_bounded_transition);
	return ksu_bst_p_security_bounded_transition ?
		       ksu_bst_p_security_bounded_transition(state, old_sid, new_sid) :
		       -ENOENT;
}
KSU_BST_DECL(int, security_inode_init_security_anon, struct inode *inode,
	     const struct qstr *name, const struct inode *context_inode)
{
	KSU_BST_ALIAS(security_inode_init_security_anon);
	return ksu_bst_p_security_inode_init_security_anon ?
		       ksu_bst_p_security_inode_init_security_anon(inode, name, context_inode) :
		       -ENOENT;
}
KSU_BST_DECL(int, mls_context_to_sid, struct policydb *p, char oldc,
	     char *scontext, struct context *context, struct sidtab *s,
	     u32 def_sid)
{
	KSU_BST_ALIAS(mls_context_to_sid);
	return ksu_bst_p_mls_context_to_sid ?
		       ksu_bst_p_mls_context_to_sid(p, oldc, scontext, context, s, def_sid) :
		       -ENOENT;
}
KSU_BST_DECL(int, policydb_context_isvalid, struct policydb *p,
	     struct context *c)
{
	KSU_BST_ALIAS(policydb_context_isvalid);
	return ksu_bst_p_policydb_context_isvalid ?
		       ksu_bst_p_policydb_context_isvalid(p, c) : -ENOENT;
}
KSU_BST_DECL(void, policydb_destroy, struct policydb *p)
{
	KSU_BST_ALIAS(policydb_destroy);
	if (ksu_bst_p_policydb_destroy)
		ksu_bst_p_policydb_destroy(p);
}
KSU_BST_DECL(int, policydb_load_isids, struct policydb *p, struct sidtab *s)
{
	KSU_BST_ALIAS(policydb_load_isids);
	return ksu_bst_p_policydb_load_isids ?
		       ksu_bst_p_policydb_load_isids(p, s) : -ENOENT;
}
KSU_BST_DECL(struct filename_trans_datum *, policydb_filenametr_search,
	     struct policydb *p, struct filename_trans_key *key)
{
	KSU_BST_ALIAS(policydb_filenametr_search);
	return ksu_bst_p_policydb_filenametr_search ?
		       ksu_bst_p_policydb_filenametr_search(p, key) : NULL;
}
KSU_BST_DECL(int, policydb_write, struct policydb *p, void *fp)
{
	KSU_BST_ALIAS(policydb_write);
	return ksu_bst_p_policydb_write ? ksu_bst_p_policydb_write(p, fp) : -ENOENT;
}
KSU_BST_DECL(int, sidtab_context_to_sid, struct sidtab *s,
	     struct context *context, u32 *sid)
{
	KSU_BST_ALIAS(sidtab_context_to_sid);
	return ksu_bst_p_sidtab_context_to_sid ?
		       ksu_bst_p_sidtab_context_to_sid(s, context, sid) : -ENOENT;
}
KSU_BST_DECL(void, sidtab_destroy, struct sidtab *s)
{
	KSU_BST_ALIAS(sidtab_destroy);
	if (ksu_bst_p_sidtab_destroy)
		ksu_bst_p_sidtab_destroy(s);
}
KSU_BST_DECL(int, avtab_alloc, struct avtab *h, u32 nrules)
{
	KSU_BST_ALIAS(avtab_alloc);
	return ksu_bst_p_avtab_alloc ? ksu_bst_p_avtab_alloc(h, nrules) : -ENOENT;
}
KSU_BST_DECL(void, avtab_destroy, struct avtab *h)
{
	KSU_BST_ALIAS(avtab_destroy);
	if (ksu_bst_p_avtab_destroy)
		ksu_bst_p_avtab_destroy(h);
}
KSU_BST_DECL(struct avtab_node *, avtab_insert_nonunique, struct avtab *h,
	     const struct avtab_key *key, const struct avtab_datum *datum)
{
	KSU_BST_ALIAS(avtab_insert_nonunique);
	return ksu_bst_p_avtab_insert_nonunique ?
		       ksu_bst_p_avtab_insert_nonunique(h, key, datum) : NULL;
}
KSU_BST_DECL(struct avtab_node *, avtab_search_node, struct avtab *h,
	     const struct avtab_key *key)
{
	KSU_BST_ALIAS(avtab_search_node);
	return ksu_bst_p_avtab_search_node ? ksu_bst_p_avtab_search_node(h, key) : NULL;
}
KSU_BST_DECL(struct avtab_node *, avtab_search_node_next,
	     struct avtab_node *node, int specified)
{
	KSU_BST_ALIAS(avtab_search_node_next);
	return ksu_bst_p_avtab_search_node_next ?
		       ksu_bst_p_avtab_search_node_next(node, specified) : NULL;
}
KSU_BST_DECL(int, __hashtab_insert, struct hashtab *h,
	     struct hashtab_node **dst, void *key, void *datum)
{
	KSU_BST_ALIAS(__hashtab_insert);
	return ksu_bst_p___hashtab_insert ?
		       ksu_bst_p___hashtab_insert(h, dst, key, datum) : -ENOENT;
}
KSU_BST_DECL(int, symtab_insert, struct symtab *s, char *name, void *datum)
{
	KSU_BST_ALIAS(symtab_insert);
	return ksu_bst_p_symtab_insert ? ksu_bst_p_symtab_insert(s, name, datum) : -ENOENT;
}
KSU_BST_DECL(void *, symtab_search, struct symtab *s, const char *name)
{
	KSU_BST_ALIAS(symtab_search);
	return ksu_bst_p_symtab_search ? ksu_bst_p_symtab_search(s, name) : NULL;
}
KSU_BST_DECL(void, ebitmap_destroy, struct ebitmap *e)
{
	KSU_BST_ALIAS(ebitmap_destroy);
	if (ksu_bst_p_ebitmap_destroy)
		ksu_bst_p_ebitmap_destroy(e);
}

/* ============ rename call sites ============ */
#define path_umount ksu_bst_path_umount
#define path_mount ksu_bst_path_mount
#define ksys_unshare ksu_bst_ksys_unshare
#define set_fs_pwd ksu_bst_set_fs_pwd
#define ns_get_path ksu_bst_ns_get_path
#define change_pid ksu_bst_change_pid
#define current_is_single_threaded ksu_bst_current_is_single_threaded
#define task_work_add ksu_bst_task_work_add
#define alloc_uid ksu_bst_alloc_uid
#define set_cred_ucounts ksu_bst_set_cred_ucounts
#define seccomp_filter_release ksu_bst_seccomp_filter_release
#define ext4_unregister_sysfs ksu_bst_ext4_unregister_sysfs
#define kallsyms_lookup ksu_bst_kallsyms_lookup
#define kallsyms_lookup_size_offset ksu_bst_kallsyms_lookup_size_offset
#define kallsyms_lookup_name ksu_bst_kallsyms_lookup_name
#define __arm64_sys_close ksu_bst___arm64_sys_close
#define __arm64_sys_setns ksu_bst___arm64_sys_setns
#define __set_fixmap ksu_bst___set_fixmap
#define copy_to_kernel_nofault ksu_bst_copy_to_kernel_nofault
#define strncpy_from_user_nofault ksu_bst_strncpy_from_user_nofault
#define dcache_clean_inval_poc ksu_bst_dcache_clean_inval_poc
#define register_kprobe ksu_bst_register_kprobe
#define unregister_kprobe ksu_bst_unregister_kprobe
#define register_kretprobe ksu_bst_register_kretprobe
#define unregister_kretprobe ksu_bst_unregister_kretprobe
#define avc_has_perm ksu_bst_avc_has_perm
#define avc_ss_reset ksu_bst_avc_ss_reset
#define selnl_notify_policyload ksu_bst_selnl_notify_policyload
#define selinux_status_update_policyload ksu_bst_selinux_status_update_policyload
#define security_bounded_transition ksu_bst_security_bounded_transition
#define security_inode_init_security_anon ksu_bst_security_inode_init_security_anon
#define mls_context_to_sid ksu_bst_mls_context_to_sid
#define policydb_context_isvalid ksu_bst_policydb_context_isvalid
#define policydb_destroy ksu_bst_policydb_destroy
#define policydb_load_isids ksu_bst_policydb_load_isids
#define policydb_filenametr_search ksu_bst_policydb_filenametr_search
#define policydb_write ksu_bst_policydb_write
#define sidtab_context_to_sid ksu_bst_sidtab_context_to_sid
#define sidtab_destroy ksu_bst_sidtab_destroy
#define avtab_alloc ksu_bst_avtab_alloc
#define avtab_destroy ksu_bst_avtab_destroy
#define avtab_insert_nonunique ksu_bst_avtab_insert_nonunique
#define avtab_search_node ksu_bst_avtab_search_node
#define avtab_search_node_next ksu_bst_avtab_search_node_next
#define __hashtab_insert ksu_bst___hashtab_insert
#define symtab_insert ksu_bst_symtab_insert
#define symtab_search ksu_bst_symtab_search
#define ebitmap_destroy ksu_bst_ebitmap_destroy

#endif /* __KSU_BST_SHIM_H */
