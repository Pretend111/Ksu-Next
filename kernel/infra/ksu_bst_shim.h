/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ksu_bst_shim.h - prototypes + data getters for kernel symbols that are
 * present in the target kernel but not EXPORT_SYMBOL'ed (BlueStacks Air
 * 5.15.137 and other non-GKI kernels).
 *
 * The matching global definitions live in infra/ksu_bst_shim.c: each wrapper
 * carries the SAME name as the kernel symbol, so call sites bind to the
 * wrapper at module link time without any macro renaming (which would break
 * kernel headers declaring the same symbols with attributes).
 *
 * Resolution uses kallsyms_lookup_name, bootstrapped via the module
 * parameter `ksu_bst_kln_addr` set by the initrd boot script.
 *
 * kprobe symbols do not exist in this kernel (CONFIG_KPROBES=n): their
 * wrappers return -ENOTSUPP so callers fall back to tracepoint paths.
 */
#ifndef __KSU_BST_SHIM_H
#define __KSU_BST_SHIM_H

#include <linux/types.h>
#include <linux/uidgid.h>
#include <asm/pgtable-types.h>
#include <linux/pid.h>
#include <linux/task_work.h>
#include <asm/fixmap.h>
#include "infra/symbol_resolver.h"
#include "klog.h"

/* ============ kallsyms_lookup_name bootstrap (insmod param) ============ */
extern unsigned long long ksu_bst_kln_addr;
extern unsigned long (*ksu_bst_kln_fn)(const char *name);

static inline unsigned long ksu_bst_kln(const char *name)
{
	if (unlikely(!ksu_bst_kln_fn))
		return 0;
	return ksu_bst_kln_fn(name);
}

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
	static inline ctype *ksu_bst_ptr_##name(void)                          \
	{                                                                      \
		return (ctype *)ksu_bst_a_##name();                            \
	}

KSU_BST_DATA(struct mm_struct, init_mm)
KSU_BST_DATA(struct selinux_state, selinux_state)
KSU_BST_DATA(struct lsm_blob_sizes, selinux_blob_sizes)
KSU_BST_DATA(struct proc_ns_operations, mntns_operations)
KSU_BST_DATA(struct tracepoint, __tracepoint_sys_enter)
KSU_BST_DATA(struct rw_semaphore, uts_sem)

/* Data symbols are accessed via ksu_bst_ptr_*() at rewritten call sites.
 * selinux_blob_sizes is special: selinux's objsec.h static inline helpers
 * bind to the symbol name directly, so infra/ksu_bst_shim.c defines a
 * same-name copy synced from the kernel at init (ksu_bst_sync_data_symbols,
 * blob offsets are boot-constant). */
void ksu_bst_sync_data_symbols(void);

/* ============ wrapper prototypes (same names as kernel symbols) ============ */
struct mm_struct;
struct selinux_state;
struct selinux_avc;
struct selinux_blob_sizes;
struct proc_ns_operations;
struct tracepoint;
struct rw_semaphore;
struct path;
struct fs_struct;
struct task_struct;
struct pid;
struct cred;
struct user_struct;
struct super_block;
struct pt_regs;
struct inode;
struct qstr;
struct kprobe;
struct kretprobe;
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
struct common_audit_data;
struct callback_head;

int path_umount(struct path *path, int flags);
int path_mount(const char *dev_name, struct path *path, const char *type_page,
	       unsigned long flags, void *data_page);
int ksys_unshare(unsigned long unshare_flags);
void set_fs_pwd(struct fs_struct *fs, const struct path *path);
int ns_get_path(struct path *path, struct task_struct *task,
		const struct proc_ns_operations *ns_ops);
void change_pid(struct task_struct *task, enum pid_type type, struct pid *pid);
bool current_is_single_threaded(void);
int task_work_add(struct task_struct *task, struct callback_head *twork,
		  enum task_work_notify_mode mode);
struct user_struct *alloc_uid(kuid_t uid);
int set_cred_ucounts(struct cred *cred);
void seccomp_filter_release(struct task_struct *tsk);
void ext4_unregister_sysfs(struct super_block *sb);

const char *kallsyms_lookup(unsigned long addr, unsigned long *symbolsize,
			    unsigned long *offset, char **modname,
			    char *namebuf);
int kallsyms_lookup_size_offset(unsigned long addr, unsigned long *symbolsize,
				unsigned long *offset);
unsigned long kallsyms_lookup_name(const char *name);

long __arm64_sys_close(const struct pt_regs *regs);
long __arm64_sys_setns(const struct pt_regs *regs);

void __set_fixmap(enum fixed_addresses idx, phys_addr_t phys, pgprot_t flags);
long copy_to_kernel_nofault(void *dst, const void *src, size_t size);
long strncpy_from_user_nofault(char *dst, const void __user *src, long count);
void dcache_clean_inval_poc(unsigned long start, unsigned long end);

int register_kprobe(struct kprobe *p);
void unregister_kprobe(struct kprobe *p);
int register_kretprobe(struct kretprobe *rp);
void unregister_kretprobe(struct kretprobe *rp);

int avc_has_perm(struct selinux_state *state, u32 ssid, u32 tsid, u16 tclass,
		 u32 requested, struct common_audit_data *auditdata);
int avc_ss_reset(struct selinux_avc *avc, u32 seqno);
void selnl_notify_policyload(u32 seqno);
void selinux_status_update_policyload(struct selinux_state *state, int seqno);
int security_bounded_transition(struct selinux_state *state, u32 old_sid,
				u32 new_sid);
int security_inode_init_security_anon(struct inode *inode, const struct qstr *name,
				      const struct inode *context_inode);
int mls_context_to_sid(struct policydb *p, char oldc, char *scontext,
		       struct context *context, struct sidtab *s, u32 def_sid);
int policydb_context_isvalid(struct policydb *p, struct context *c);
void policydb_destroy(struct policydb *p);
int policydb_load_isids(struct policydb *p, struct sidtab *s);
struct filename_trans_datum *policydb_filenametr_search(struct policydb *p,
							struct filename_trans_key *key);
int policydb_write(struct policydb *p, void *fp);
int sidtab_context_to_sid(struct sidtab *s, struct context *context, u32 *sid);
void sidtab_destroy(struct sidtab *s);
int avtab_alloc(struct avtab *h, u32 nrules);
void avtab_destroy(struct avtab *h);
struct avtab_node *avtab_insert_nonunique(struct avtab *h,
					  const struct avtab_key *key,
					  const struct avtab_datum *datum);
struct avtab_node *avtab_search_node(struct avtab *h,
				     const struct avtab_key *key);
struct avtab_node *avtab_search_node_next(struct avtab_node *node,
					  int specified);
int __hashtab_insert(struct hashtab *h, struct hashtab_node **dst, void *key,
		     void *datum);
int symtab_insert(struct symtab *s, char *name, void *datum);
void *symtab_search(struct symtab *s, const char *name);
void ebitmap_destroy(struct ebitmap *e);

#endif /* __KSU_BST_SHIM_H */
