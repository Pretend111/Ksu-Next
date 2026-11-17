/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * bst_hide.h - existence adjudication for the BlueStacks deblur layer.
 */

#ifndef __KSU_INFRA_BST_HIDE_H
#define __KSU_INFRA_BST_HIDE_H

/*
 * Installs the openat/openat2/faccessat/faccessat2/newfstatat/statx and
 * getdents64 hooks.  Must run after ksu_syscall_hook_init() (the table has to
 * be resolved) and before user space starts probing, i.e. from
 * kernelsu_init().
 */
void ksu_bst_hide_init(void);

#endif /* __KSU_INFRA_BST_HIDE_H */
