/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ksu_ss_shim.h - route SELinux "ss" internal calls through kallsyms.
 *
 * GKI and custom kernels do not EXPORT_SYMBOL the SELinux ss internals
 * (ebitmap_*, mls_*, sidtab_*, cond_compute_av, policydb_read). Android GKI
 * kernels carry a kallsyms fallback for module symbol resolution, but
 * third-party kernels (e.g. BlueStacks Air 5.15.137) do not, so direct
 * references make the module fail to load with "Unknown symbol".
 *
 * This header must be included AFTER the SELinux ss headers. It defines
 * lazily-resolved function pointers and renames each call site to a static
 * inline wrapper with the exact prototype from android13-5.15.137 sources.
 */
#ifndef __KSU_SS_KALLSYMS_SHIM_H
#define __KSU_SS_KALLSYMS_SHIM_H

#include "infra/symbol_resolver.h"
#include "klog.h"

#define KSU_SS_SHIM_DECL(ret, name, args...)                                   \
	static ret (*ksu_ss_p_##name)(args);                                   \
	static bool ksu_ss_tried_##name;                                       \
	static ret ksu_ss_##name(args)

#define KSU_SS_SHIM_RESOLVE(name)                                              \
	do {                                                                   \
		if (!ksu_ss_p_##name && !ksu_ss_tried_##name) {                \
			ksu_ss_tried_##name = true;                            \
			ksu_ss_p_##name = (void *)find_kernel_symbol_exact(#name); \
			if (!ksu_ss_p_##name)                                  \
				pr_warn_once("KernelSU: ss shim: " #name " not found via kallsyms\n"); \
		}                                                              \
	} while (0)

#define KSU_SS_SHIM_ALIAS(name)                                                \
	do {                                                                   \
		KSU_SS_SHIM_RESOLVE(name);                                     \
	} while (0)

/* ---- ebitmap ---- */
KSU_SS_SHIM_DECL(int, ebitmap_cmp, struct ebitmap *e1, struct ebitmap *e2)
{
	KSU_SS_SHIM_ALIAS(ebitmap_cmp);
	return ksu_ss_p_ebitmap_cmp ? ksu_ss_p_ebitmap_cmp(e1, e2) : 0;
}
KSU_SS_SHIM_DECL(int, ebitmap_contains, struct ebitmap *e1, struct ebitmap *e2,
		 u32 last_e2bit)
{
	KSU_SS_SHIM_ALIAS(ebitmap_contains);
	return ksu_ss_p_ebitmap_contains ? ksu_ss_p_ebitmap_contains(e1, e2, last_e2bit) : 0;
}
KSU_SS_SHIM_DECL(int, ebitmap_get_bit, struct ebitmap *e, unsigned long bit)
{
	KSU_SS_SHIM_ALIAS(ebitmap_get_bit);
	return ksu_ss_p_ebitmap_get_bit ? ksu_ss_p_ebitmap_get_bit(e, bit) : 0;
}
KSU_SS_SHIM_DECL(int, ebitmap_set_bit, struct ebitmap *e, unsigned long bit,
		 int value)
{
	KSU_SS_SHIM_ALIAS(ebitmap_set_bit);
	return ksu_ss_p_ebitmap_set_bit ? ksu_ss_p_ebitmap_set_bit(e, bit, value) : -EINVAL;
}

/* ---- mls ---- */
KSU_SS_SHIM_DECL(int, mls_compute_context_len, struct policydb *p,
		 struct context *context)
{
	KSU_SS_SHIM_ALIAS(mls_compute_context_len);
	return ksu_ss_p_mls_compute_context_len ?
		       ksu_ss_p_mls_compute_context_len(p, context) : 0;
}
KSU_SS_SHIM_DECL(void, mls_sid_to_context, struct policydb *p,
		 struct context *context, char **scontext)
{
	KSU_SS_SHIM_ALIAS(mls_sid_to_context);
	if (ksu_ss_p_mls_sid_to_context)
		ksu_ss_p_mls_sid_to_context(p, context, scontext);
}

/* ---- sidtab ---- */
KSU_SS_SHIM_DECL(struct sidtab_entry *, sidtab_search_entry, struct sidtab *s,
		 u32 sid)
{
	KSU_SS_SHIM_ALIAS(sidtab_search_entry);
	return ksu_ss_p_sidtab_search_entry ? ksu_ss_p_sidtab_search_entry(s, sid) : NULL;
}
KSU_SS_SHIM_DECL(int, sidtab_sid2str_get, struct sidtab *s,
		 struct sidtab_entry *entry, char **out, u32 *out_len)
{
	KSU_SS_SHIM_ALIAS(sidtab_sid2str_get);
	return ksu_ss_p_sidtab_sid2str_get ?
		       ksu_ss_p_sidtab_sid2str_get(s, entry, out, out_len) : -ENOENT;
}
KSU_SS_SHIM_DECL(void, sidtab_sid2str_put, struct sidtab *s,
		 struct sidtab_entry *entry, const char *str, u32 str_len)
{
	KSU_SS_SHIM_ALIAS(sidtab_sid2str_put);
	if (ksu_ss_p_sidtab_sid2str_put)
		ksu_ss_p_sidtab_sid2str_put(s, entry, str, str_len);
}

/* ---- conditional ---- */
KSU_SS_SHIM_DECL(void, cond_compute_av, struct avtab *ctab,
		 struct avtab_key *key, struct av_decision *avd,
		 struct extended_perms *xperms)
{
	KSU_SS_SHIM_ALIAS(cond_compute_av);
	if (ksu_ss_p_cond_compute_av)
		ksu_ss_p_cond_compute_av(ctab, key, avd, xperms);
}

/* ---- policydb ---- */
KSU_SS_SHIM_DECL(int, policydb_read, struct policydb *p, void *fp)
{
	KSU_SS_SHIM_ALIAS(policydb_read);
	return ksu_ss_p_policydb_read ? ksu_ss_p_policydb_read(p, fp) : -ENOENT;
}

#define ebitmap_cmp ksu_ss_ebitmap_cmp
#define ebitmap_contains ksu_ss_ebitmap_contains
#define ebitmap_get_bit ksu_ss_ebitmap_get_bit
#define ebitmap_set_bit ksu_ss_ebitmap_set_bit
#define mls_compute_context_len ksu_ss_mls_compute_context_len
#define mls_sid_to_context ksu_ss_mls_sid_to_context
#define sidtab_search_entry ksu_ss_sidtab_search_entry
#define sidtab_sid2str_get ksu_ss_sidtab_sid2str_get
#define sidtab_sid2str_put ksu_ss_sidtab_sid2str_put
#define cond_compute_av ksu_ss_cond_compute_av
#define policydb_read ksu_ss_policydb_read

#endif /* __KSU_SS_KALLSYMS_SHIM_H */
